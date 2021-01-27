package main

import (
	"bufio"
	"bytes"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This only contains helpers so far

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func newTestConfig(t *testing.T) (string, *pcopy.Config) {
	config := pcopy.NewConfig()
	tempDir := t.TempDir()

	key, cert, err := pcopy.GenerateKeyAndCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	clipboardDir := filepath.Join(tempDir, "clipboard")
	if err := os.Mkdir(clipboardDir, 0700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(tempDir, "key")
	if err := ioutil.WriteFile(keyFile, []byte(key), 0700); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(tempDir, "cert")
	if err := ioutil.WriteFile(certFile, []byte(cert), 0700); err != nil {
		t.Fatal(err)
	}

	config.ServerAddr = pcopy.ExpandServerAddr("localhost:12345")
	config.ListenHTTPS = ":12345"
	config.ClipboardDir = clipboardDir
	config.KeyFile = keyFile
	config.CertFile = certFile

	filename := filepath.Join(tempDir, "config.conf")
	if err := config.WriteFile(filename); err != nil {
		t.Fatal(err)
	}

	return filename, config
}

func runTestServerRouter(t *testing.T, config *pcopy.Config) *pcopy.ServerRouter {
	server, err := pcopy.NewServerRouter(config)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			panic(err) // 'go vet' complains about 't.Fatal(err)'
		}
	}()
	return server
}

func newTestApp() (*cli.App, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	var stdin, stdout, stderr bytes.Buffer
	app := newApp()
	app.Reader = &stdin
	app.Writer = &stdout
	app.ErrWriter = &stderr
	return app, &stdin, &stdout, &stderr
}

func waitForOutput(t *testing.T, rc io.ReadCloser, waitFirstLine time.Duration, waitRest time.Duration) string {
	reader := bufio.NewReader(rc)
	lines := make(chan string)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err == nil {
				lines <- line
			} else if err == io.EOF {
				close(lines)
				break
			}
		}
	}()
	output := make([]string, 0)
	wait := waitFirstLine
loop:
	for {
		select {
		case line := <-lines:
			output = append(output, line)
			wait = waitRest
		case <-time.After(wait):
			break loop
		}
	}
	if len(output) == 0 {
		t.Fatalf("waiting for output timed out")
	}
	return strings.Join(output, "\n")
}

// FIXME: Duplicate code, move to package or use assert library
func assertFileContent(t *testing.T, config *pcopy.Config, id string, content string) {
	filename := filepath.Join(config.ClipboardDir, id)
	actualContent, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualContent) != content {
		t.Fatalf("expected %s, got %s", content, actualContent)
	}
}

func assertStrEquals(t *testing.T, expected string, actual string) {
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func assertStrContains(t *testing.T, s string, substr string) {
	if !strings.Contains(s, substr) {
		t.Fatalf("expected %s to be contained in string, but it wasn't: %s", substr, s)
	}
}
