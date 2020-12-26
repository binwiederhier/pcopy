package pcopy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const (
	purgerTicketInterval = time.Second * 10
	defaultMaxAuthAge    = time.Minute
	noAuthRequestAge     = 0
)

var (
	hmacAuthFormat        = "HMAC %d %d %s" // timestamp ttl b64-hmac
	hmacAuthRegex         = regexp.MustCompile(`^HMAC (\d+) (\d+) (.+)$`)
	hmacAuthOverrideParam = "a"
	clipboardRegex        = regexp.MustCompile(`^/c(?:/([-_a-zA-Z0-9]+))$`)
	clipboardPathFormat   = "/c/%s"
	clipboardDefaultPath  = "/c"

	//go:embed "web/index.gohtml"
	webTemplateSource string
	webTemplate       = template.Must(template.New("index").Parse(webTemplateSource))

	//go:embed web/static
	webStaticFs embed.FS
)

type webTemplateConfig struct {
	Salt string
	PbkdfIter int
	KeyLen int
}

type server struct {
	config *Config
}

func Serve(config *Config) error {
	server := &server{config: config}
	if err := server.checkConfig(); err != nil {
		return err
	}
	if config.ExpireAfter > 0 {
		go server.clipboardPurger()
	}
	return server.listenAndServeTLS()
}

func (s *server) checkConfig() error {
	if s.config.ListenAddr == "" {
		return listenAddrMissingError
	}
	if s.config.KeyFile == "" {
		return keyFileMissingError
	}
	if s.config.CertFile == "" {
		return certFileMissingError
	}
	if unix.Access(s.config.ClipboardDir, unix.W_OK) != nil {
		return clipboardDirNotWritableError
	}
	return nil
}

func (s *server) listenAndServeTLS() error {
	http.HandleFunc("/info", s.handleInfo)
	http.HandleFunc("/verify", s.handleVerify)
	http.HandleFunc("/install", s.handleInstall)
	http.HandleFunc("/join", s.handleJoin)
	http.HandleFunc("/download", s.handleDownload)
	http.HandleFunc("/c/", s.handleClipboard)
	http.HandleFunc("/c", s.handleClipboard)

	if s.config.WebUI {
		http.HandleFunc("/", s.handleWebRoot)
	}

	return http.ListenAndServeTLS(s.config.ListenAddr, s.config.CertFile, s.config.KeyFile, nil)
}

func (s *server) clipboardPurger() {
	ticker := time.NewTicker(purgerTicketInterval)
	for {
		<-ticker.C
		files, err := ioutil.ReadDir(s.config.ClipboardDir)
		if err != nil {
			log.Printf("failed to read clipboard dir: %s", err.Error())
			continue
		}
		for _, f := range files {
			if time.Now().Sub(f.ModTime()) > s.config.ExpireAfter {
				if err := os.Remove(filepath.Join(s.config.ClipboardDir, f.Name())); err != nil {
					log.Printf("failed to remove clipboard entry after expiry: %s", err.Error())
				}
				log.Printf("removed expired entry %s", f.Name())
			}
		}
	}
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	salt := ""
	if s.config.Key != nil {
		salt = base64.StdEncoding.EncodeToString(s.config.Key.Salt)
	}

	response := &infoResponse{
		ServerAddr: s.config.ServerAddr,
		Salt:       salt,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
}

func (s *server) handleWebRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		var config *webTemplateConfig
		if s.config.Key != nil {
			config = &webTemplateConfig{
				Salt: base64.StdEncoding.EncodeToString(s.config.Key.Salt),
				PbkdfIter: pbkdfIter,
				KeyLen: keyLen,
			}
		} else {
			config = &webTemplateConfig{}
		}
		if err := webTemplate.Execute(w, config); err != nil {
			s.fail(w, r, http.StatusInternalServerError, err)
		}
	} else if strings.HasPrefix(r.URL.Path, "/static") {
		r.URL.Path = "/web" + r.URL.Path // This is a hack to get the embedded path
		http.FileServer(http.FS(webStaticFs)).ServeHTTP(w, r)
	}
}

func (s *server) handleClipboard(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if err := os.MkdirAll(s.config.ClipboardDir, 0700); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}

	var id string
	matches := clipboardRegex.FindStringSubmatch(r.URL.Path)
	if matches == nil {
		id = DefaultId
	} else {
		id = matches[1]
	}
	file := fmt.Sprintf("%s/%s", s.config.ClipboardDir, id)

	if r.Method == http.MethodGet {
		stat, err := os.Stat(file)
		if err != nil {
			s.fail(w, r, http.StatusNotFound, err)
			return
		}
		w.Header().Set("Length", strconv.FormatInt(stat.Size(), 10))
		f, err := os.Open(file)
		if err != nil {
			s.fail(w, r, http.StatusNotFound, err)
			return
		}
		defer f.Close()

		if _, err = io.Copy(w, f); err != nil {
			s.fail(w, r, http.StatusInternalServerError, err)
			return
		}
	} else if r.Method == http.MethodPut {
		f, err := os.Create(file)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, err)
			return
		}
		defer f.Close()

		if r.Body != nil {
			if _, err = io.Copy(f, r.Body); err != nil {
				s.fail(w, r, http.StatusInternalServerError, err)
				return
			}
			if r.Body.Close() != nil {
				s.fail(w, r, http.StatusInternalServerError, err)
				return
			}
		}
	}
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	executable, err := getExecutable()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}

	f, err := os.Open(executable)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	if _, err = io.Copy(w, f); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleInstall(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	var script string
	if s.config.ServerAddr != "" {
		script = s.installScript()
	} else {
		script = s.notConfiguredScript()
	}

	if _, err := w.Write([]byte(script)); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	var script string
	if s.config.ServerAddr != "" {
		script = s.joinScript()
	} else {
		script = s.notConfiguredScript()
	}

	if _, err := w.Write([]byte(script)); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) authorize(r *http.Request) error {
	if s.config.Key == nil {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if encodedQueryAuth, ok := r.URL.Query()[hmacAuthOverrideParam]; ok && len(encodedQueryAuth) > 0 {
		queryAuth, err := base64.StdEncoding.DecodeString(encodedQueryAuth[0])
		if err != nil {
			log.Printf("%s - %s %s - cannot decode query auth override", r.RemoteAddr, r.Method, r.RequestURI)
			return invalidAuthError
		}
		auth = string(queryAuth)
	}

	matches := hmacAuthRegex.FindStringSubmatch(auth)
	if matches == nil {
		log.Printf("%s - %s %s - auth header missing", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	timestamp, err := strconv.Atoi(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - hmac timestamp conversion: %w", r.RemoteAddr, r.Method, r.RequestURI, err)
		return invalidAuthError
	}

	ttlSecs, err := strconv.Atoi(matches[2])
	if err != nil {
		log.Printf("%s - %s %s - hmac ttl conversion: %w", r.RemoteAddr, r.Method, r.RequestURI, err)
		return invalidAuthError
	}

	hash, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		log.Printf("%s - %s %s - hmac base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return invalidAuthError
	}

	// Recalculate HMAC
	data := []byte(fmt.Sprintf("%d:%d:%s:%s", timestamp, ttlSecs, r.Method, r.URL.Path))
	hm := hmac.New(sha256.New, s.config.Key.Bytes)
	if _, err := hm.Write(data); err != nil {
		log.Printf("%s - %s %s - hmac calculation: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return invalidAuthError
	}
	rehash := hm.Sum(nil)

	// Compare HMAC in constant time (to prevent timing attacks)
	if subtle.ConstantTimeCompare(hash, rehash) != 1 {
		log.Printf("%s - %s %s - hmac invalid", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	// Compare timestamp (to prevent replay attacks)
	maxAge := defaultMaxAuthAge
	if ttlSecs > 0 {
		maxAge = time.Second * time.Duration(ttlSecs)
	}
	if maxAge > 0 {
		age := time.Now().Sub(time.Unix(int64(timestamp), 0))
		if age > maxAge {
			log.Printf("%s - %s %s - hmac request age mismatch", r.RemoteAddr, r.Method, r.RequestURI)
			return invalidAuthError
		}
	}

	return nil
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("%s - %s %s - %#v", r.RemoteAddr, r.Method, r.RequestURI, err)
	w.WriteHeader(code)
	w.Write([]byte(fmt.Sprintf("%d", code)))
}

func(s *server) notConfiguredScript() string {
	return strings.Join([]string{scriptHeader, notConfiguredCommands}, "\n")
}

func (s *server) installScript() string {
	template := strings.Join([]string{scriptHeader, installCommands, joinInstructionsCommands}, "\n")
	return s.replaceScriptVars(template)
}

func (s *server) joinScript() string {
	template := strings.Join([]string{scriptHeader, joinCommands}, "\n")
	return s.replaceScriptVars(template)
}

func (s *server) replaceScriptVars(template string) string {
	template = strings.ReplaceAll(template, "${serverAddr}", ExpandServerAddr(s.config.ServerAddr))
	template = strings.ReplaceAll(template, "${key}", EncodeKey(s.config.Key))
	return template
}

func getExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	realpath, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}

	return realpath, nil
}

// infoResponse is the response returned by the / endpoint
type infoResponse struct {
	ServerAddr string `json:"serverAddr"`
	Salt       string `json:"salt"`
}

const certCommonName = "pcopy"

var listenAddrMissingError = errors.New("listen address missing, add 'ListenAddr' to config or pass -listen")
var keyFileMissingError = errors.New("private key file missing, add 'KeyFile' to config or pass -keyfile")
var certFileMissingError = errors.New("certificate file missing, add 'CertFile' to config or pass -certfile")
var clipboardDirNotWritableError = errors.New("clipboard dir not writable by user")
var invalidAuthError = errors.New("invalid auth")

const scriptHeader = `#!/bin/sh
set -eu
`
const notConfiguredCommands = `echo 'Server not configured to allow simple install.'
echo 'If you are the administrator, set ServerAddr in config.'
`
const installCommands = `if [ ! -f /usr/bin/pcopy ]; then
  [ $(id -u) -eq 0 ] || { echo 'Must be root to install'; exit 1; }
  curl -sk https://${serverAddr}/download > /usr/bin/pcopy
  chmod +x /usr/bin/pcopy
  [ -f /usr/bin/pcp ] || ln -s /usr/bin/pcopy /usr/bin/pcp
  [ -f /usr/bin/ppaste ] || ln -s /usr/bin/pcopy /usr/bin/ppaste
  echo "Successfully installed /usr/bin/pcopy."
fi
`
const joinInstructionsCommands = `echo "To join this clipboard, run 'pcopy join ${serverAddr}', or type 'pcopy -help' for more help'."
`
const joinCommands = `PCOPY_KEY=${key} /usr/bin/pcopy join -auto ${serverAddr}
`
