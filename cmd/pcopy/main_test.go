package main

import (
	"heckel.io/pcopy"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This only contains helpers so far

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func tempFDs(t *testing.T) *stdFDs {
	var err error
	dir := t.TempDir()
	stdin, err := os.OpenFile(filepath.Join(dir, "stdin"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	return &stdFDs{
		in:  stdin,
		out: stdout,
		err: stderr,
	}
}

func tempFDsWithSTDIN(t *testing.T, writeToSTDIN string) *stdFDs {
	fds := tempFDs(t)
	fds.in.WriteString(writeToSTDIN)
	fds.in.Seek(0, 0)
	return fds
}

func readFullFD(t *testing.T, fd *os.File) string {
	if _, err := fd.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(fd)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newTestConfig(t *testing.T) (string, *pcopy.Config) {
	config := pcopy.NewConfig()
	tempDir := t.TempDir()

	key, cert, err := pcopy.GenerateKeyAndCert()
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

func runTestServer(t *testing.T, config *pcopy.Config) *pcopy.Server {
	server, err := pcopy.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err) // 'go vet' complains about 't.Fatal(err)'
		}
	}()
	return server
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

func assertFdContains(t *testing.T, fd *os.File, substr string) {
	s := readFullFD(t, fd)
	if !strings.Contains(s, substr) {
		t.Fatalf("expected %s to be contained in string, but it wasn't: %s", substr, s)
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
