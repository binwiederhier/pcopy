package pcopy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

type handler struct {
	config *Config
}

func Serve(config *Config) error  {
	server := &http.Server{
		Addr: config.ListenAddr,
		Handler: &handler{
			config: config,
		},
	}

	return server.ListenAndServeTLS(config.CertFile, config.KeyFile)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(h.config.CacheDir, 0700); err != nil {
		panic(err)
	}

	fileIdRegexp := regexp.MustCompile(`^/([-_a-zA-Z0-9]+)$`)
	matches := fileIdRegexp.FindStringSubmatch(r.RequestURI)
	if matches == nil {
		panic("invalid fileID")
	}
	fileId := matches[1]
	file := fmt.Sprintf("%s/%s", h.config.CacheDir, fileId)

	if r.Method == http.MethodGet {
		f, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		if _, err = io.Copy(w, f); err != nil {
			panic(err)
		}
	} else if r.Method == http.MethodPut {
		f, err := os.Create(file)
		if err != nil {
			panic(err)
		}
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

