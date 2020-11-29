package pcopy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

type server struct {
	config *Config
}

func Serve(config *Config) error  {
	server := &server{
		config: config,
	}

	http.Handle("/", server)
	return http.ListenAndServe(config.ListenAddr, nil)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := os.MkdirAll(s.config.CacheDir, 0700); err != nil {
		panic(err)
	}

	fileIdRegexp := regexp.MustCompile(`^/([-_a-zA-Z0-9]+)$`)
	matches := fileIdRegexp.FindStringSubmatch(r.RequestURI)
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
