package pcopy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
)

func Serve(config *Config) error  {
	http.HandleFunc("/", handler)
	return http.ListenAndServe(config.ListenAddr, nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	cacheDir := fmt.Sprintf("%s/.cache/pcopy", homeDir)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		panic(err)
	}

	fileIdRegexp := regexp.MustCompile(`^/([-_a-z0-9]+)$`)
	matches := fileIdRegexp.FindStringSubmatch(r.RequestURI)
	if matches == nil {
		panic("invalid fileID")
	}
	fileId := matches[1]
	file := fmt.Sprintf("%s/%s", cacheDir, fileId)

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
