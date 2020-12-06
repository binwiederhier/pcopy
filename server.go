package pcopy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type server struct {
	config *Config
}

func Serve(config *Config) error {
	server := &server{config: config}
	if err := server.checkConfig(); err != nil {
		return err
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
	if unix.Access(s.config.CacheDir, unix.W_OK) != nil {
		return cacheDirNotWritableError
	}
	return nil
}

func (s *server) listenAndServeTLS() error {
	http.HandleFunc("/", s.handleInfo)
	http.HandleFunc("/verify", s.handleVerify)
	http.HandleFunc("/install", s.handleInstall)
	http.HandleFunc("/join", s.handleJoin)
	http.HandleFunc("/download", s.handleDownload)
	http.HandleFunc("/clip/", s.handleClipboard)

	return http.ListenAndServeTLS(s.config.ListenAddr, s.config.CertFile, s.config.KeyFile, nil)
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	salt := ""
	if s.config.Key != nil {
		salt = base64.StdEncoding.EncodeToString(s.config.Key.Salt)
	}

	response := &infoResponse{
		Version: 1,
		Salt:    salt,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, s.config.MaxRequestAge); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
}

func (s *server) handleClipboard(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, s.config.MaxRequestAge); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if err := os.MkdirAll(s.config.CacheDir, 0700); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}

	re := regexp.MustCompile(`^/clip/([-_a-zA-Z0-9]+)$`)
	matches := re.FindStringSubmatch(r.RequestURI)
	if matches == nil {
		s.fail(w, r, http.StatusBadRequest, invalidFileError)
		return
	}
	fileId := matches[1]
	file := fmt.Sprintf("%s/%s", s.config.CacheDir, fileId)

	if r.Method == http.MethodGet {
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
	if err := s.authorize(r, s.config.MaxJoinAge); err != nil {
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

func (s *server) authorize(r *http.Request, maxRequestAge int) error {
	if s.config.Key == nil {
		return nil
	}

	re := regexp.MustCompile(`^HMAC v1 (\d+) (.+)$`)
	matches := re.FindStringSubmatch(r.Header.Get("Authorization"))
	if matches == nil {
		log.Printf("%s - %s %s - auth header missing", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	timestamp, err := strconv.Atoi(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - hmac number conversion: %w", r.RemoteAddr, r.Method, r.RequestURI, err)
		return invalidAuthError
	}

	hash, err := base64.StdEncoding.DecodeString(matches[2])
	if err != nil {
		log.Printf("%s - %s %s - hmac base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return invalidAuthError
	}

	// Recalculate HMAC
	data := []byte(fmt.Sprintf("%d:%s:%s", timestamp, r.Method, r.RequestURI))
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
	if math.Abs(float64(time.Now().Unix()) - float64(timestamp)) > float64(maxRequestAge) {
		log.Printf("%s - %s %s - hmac request age mismatch", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	return nil
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("%s - %s %s - %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
	w.WriteHeader(code)
}

func(s *server) notConfiguredScript() string {
	return strings.Join([]string{scriptHeader, notConfiguredCommands}, "\n")
}

func (s *server) installScript() string {
	template := strings.Join([]string{scriptHeader, installCommands, joinInstructionsCommands}, "\n")
	return s.replaceScriptVars(template)
}

func (s *server) joinScript() string {
	template := strings.Join([]string{scriptHeader, installCommands, joinCommands}, "\n")
	return s.replaceScriptVars(template)
}

func (s *server) replaceScriptVars(template string) string {
	template = strings.ReplaceAll(template, "${serverAddr}", s.config.ServerAddr)
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

var listenAddrMissingError = errors.New("listen address missing, add 'ListenAddr' to config or pass -listen")
var keyFileMissingError = errors.New("private key file missing, add 'KeyFile' to config or pass -keyfile")
var certFileMissingError = errors.New("certificate file missing, add 'CertFile' to config or pass -certfile")
var cacheDirNotWritableError = errors.New("cache dir not writable by user")
var invalidAuthError = errors.New("invalid auth")
var invalidFileError = errors.New("invalid file name")

const scriptHeader = `#!/bin/sh
set -e
`
const notConfiguredCommands = `echo 'Server not configured to allow simple install.
echo 'If you are the administrator, set ServerAddr in config.
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
const joinInstructionsCommands = `echo "To join this server's clipboard, use the following command:"
echo
echo '  $ pcopy join ${serverAddr}'
echo
echo "For more help, type 'pcopy -help'."
`
const joinCommands = `PCOPY_KEY=${key} /usr/bin/pcopy join -auto ${serverAddr}
`