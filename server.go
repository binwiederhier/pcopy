package pcopy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

type Server struct {
	config *Config
}

func NewServer(config *Config) *Server {
	return &Server{
		config: config,
	}
}

func (s *Server) ListenAndServeTLS() error {
	http.HandleFunc("/", s.handleInfo)
	http.HandleFunc("/verify", s.handleVerify)
	http.HandleFunc("/clip/", s.handleClip)

	return http.ListenAndServeTLS(s.config.ListenAddr, s.config.CertFile, s.config.KeyFile, nil)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	response := &infoResponse{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(s.config.Salt),
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	
}

func (s *Server) handleClip(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(s.config.CacheDir, 0700); err != nil {
		panic(err)
	}

	re := regexp.MustCompile(`^/clip/([-_a-zA-Z0-9]+)$`)
	matches := re.FindStringSubmatch(r.RequestURI)
	if matches == nil {
		panic("invalid fileID")
	}
	fileId := matches[1]
	file := fmt.Sprintf("%s/%s", s.config.CacheDir, fileId)

	if r.Method == http.MethodGet {
		f, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		if _, err = io.Copy(w, f); err != nil {
			panic(err)
		}
	} else if r.Method == http.MethodPut {
		f, err := os.Create(file)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		if r.Body != nil {
			if _, err = io.Copy(f, r.Body); err != nil {
				panic(err)
			}
			if r.Body.Close() != nil {
				panic(err)
			}
		}
	}
}

