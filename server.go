package pcopy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

type server struct {
	config *Config
}

func Serve(config *Config) error {
	server := &server{config: config}
	return server.listenAndServeTLS()
}

func (s *server) listenAndServeTLS() error {
	http.HandleFunc("/", s.handleInfo)
	http.HandleFunc("/verify", s.handleVerify)
	http.HandleFunc("/install", s.handleInstall)
	http.HandleFunc("/get", s.handleGet)
	http.HandleFunc("/clip/", s.handleClip)

	return http.ListenAndServeTLS(s.config.ListenAddr, s.config.CertFile, s.config.KeyFile, nil)
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	salt := ""
	if s.config.Salt != nil {
		salt = base64.StdEncoding.EncodeToString(s.config.Salt)
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
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
}

func (s *server) handleClip(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
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
		s.fail(w, r, http.StatusBadRequest, invalidFileId)
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

func (s *server) handleGet(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	executable, err := GetExecutable()
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
		script = "#!/bin/bash\n" +
			"set -e\n" +
			"[ $(id -u) -eq 0 ] || { echo 'Must be root to install'; exit 1; }\n" +
			fmt.Sprintf("curl -sk https://%s/get > /usr/bin/pcopy\n", s.config.ServerAddr) +
			"chmod +x /usr/bin/pcopy\n" +
			"[ -f /usr/bin/pcp ] || ln -s /usr/bin/pcopy /usr/bin/pcp\n" +
			"[ -f /usr/bin/ppaste ] || ln -s /usr/bin/pcopy /usr/bin/ppaste\n" +
			"echo \"Successfully installed /usr/bin/pcopy.\"\n" +
			"echo \"To join this server's clipboard, use the following command:\"\n" +
			"echo\n" +
			fmt.Sprintf("echo '  $ pcopy join %s'\n", s.config.ServerAddr) +
			"echo\n" +
			"echo \"For more help, type 'pcopy -help'.\"\n"

	} else {
		script = "#!/bin/bash\n" +
			"echo 'Server not configured to allow simple install.'\n" +
			"echo 'If you are the administrator, set ServerAddr in config.'\n"
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
	hm := hmac.New(sha256.New, s.config.Key)
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
	if math.Abs(float64(time.Now().Unix()) - float64(timestamp)) > float64(s.config.MaxRequestAge) {
		log.Printf("%s - %s %s - hmac request age mismatch", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	return nil
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("%s - %s %s - %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
	w.WriteHeader(code)
}

var invalidAuthError = errors.New("invalid auth")
var invalidFileId = errors.New("invalid file ID")