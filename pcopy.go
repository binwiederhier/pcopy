package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"time"
)
import _ "database/sql"
import _ "github.com/go-sql-driver/mysql"

func main() {
	rand.Seed(time.Now().UnixNano())

	if len(os.Args) < 2 {
		fmt.Println("Syntax: pcopy (copy|paste|serve)")
		os.Exit(1)
	}

	if os.Args[1] == "copy" {
		flags := flag.NewFlagSet("copy", flag.ExitOnError)
		server := flags.String("server", "", "Server address")
		fileId := flags.String("id", "default", "File ID")

		if err := flags.Parse(os.Args[2:]); err != nil {
			panic(err)
		}

		stat, err := os.Stdin.Stat()
		if err != nil {
			panic(err)
		}
		isTerm := (stat.Mode() & os.ModeCharDevice) != 0

		if !isTerm {
			cp(*server, *fileId, os.Stdin)
		} else {
			if flags.NArg() < 1 {
				panic("syntax err2")
			}

			fileName := flags.Arg(0)
			file, err := os.Open(fileName)
			if err != nil {
				panic(err)
			}

			cp(*server, *fileId, file)
		}
	} else if os.Args[1] == "paste" {
		flags := flag.NewFlagSet("paste", flag.ExitOnError)
		server := flags.String("server", "", "Server address")
		fileId := flags.String("id", "default", "File ID")
		if err := flags.Parse(os.Args[2:]); err != nil {
			panic(err)
		}

		stat, err := os.Stdout.Stat()
		if err != nil {
			panic(err)
		}
		isTerm := (stat.Mode() & os.ModeCharDevice) != 0

		if !isTerm {
			println("not a terminal")
			paste(*server, *fileId, os.Stdout)
		} else {
			println("a terminal")
			if flags.NArg() < 1 {
				panic("syntax err2")
			}

			fileName := flags.Arg(0)
			file, err := os.Create(fileName)
			if err != nil {
				panic(err)
			}

			paste(*server, *fileId, file)
		}
	} else if os.Args[1] == "serve" {
		flags := flag.NewFlagSet("serve", flag.ExitOnError)
		listenAddr := flags.String("l", "0.0.0.0:1986", "Listen address")
		if err := flags.Parse(os.Args[2:]); err != nil {
			panic(err)
		}

		serve(*listenAddr)
	} else {
		fmt.Println("Syntax: myhammer (copy|run)")
		os.Exit(1)
	}
}

func cp(endpoint string, fileId string, reader io.Reader) {
	client := &http.Client{}

	url := fmt.Sprintf("%s/%s", endpoint, fileId)
	req, err := http.NewRequest(http.MethodPut, url, reader)
	if err != nil {
		panic(err)
	}

	if _, err := client.Do(req); err != nil {
		panic(err)
	}
}

func paste(endpoint string, fileId string, writer io.Writer) {
	client := &http.Client{}

	url := fmt.Sprintf("%s/%s", endpoint, fileId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	} else if resp.Body == nil {
		panic("body empty")
	}

	if _, err := io.Copy(writer, resp.Body); err != nil {
		panic(err)
	}
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

func serve(listenAddr string)  {
	http.HandleFunc("/", handler)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		panic(err)
	}
}