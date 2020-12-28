package pcopy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestServe_InfoUnprotected(t *testing.T) {
	config := newTestConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handleInfo(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("unexpected status code: got %v want %v", status, http.StatusOK)
	}

	expected := `{"serverAddr":"localhost:12345","salt":""}`
	if strings.TrimSpace(rr.Body.String()) != expected {
		t.Errorf("unexpected body: got %v want %v", strings.TrimSpace(rr.Body.String()), expected)
	}
}

func TestServe_InfoProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handleInfo(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("unexpected status code: got %v want %v", status, http.StatusOK)
	}

	expected := `{"serverAddr":"localhost:12345","salt":"c29tZSBzYWx0"}`
	if strings.TrimSpace(rr.Body.String()) != expected {
		t.Errorf("unexpected body: got %v want %v", strings.TrimSpace(rr.Body.String()), expected)
	}
}

func newTestServer(t *testing.T, config *Config) *server {
	server, err := newServer(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func newTestConfig(t *testing.T) *Config {
	config := newConfig()
	t.Cleanup(func() { cleanupTestConfig(config) })

	key, cert, err := GenerateKeyAndCert()
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := ioutil.TempFile("", fmt.Sprintf("pcopytest.%s.*.key", t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyFile.Write([]byte(key)); err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()

	certFile, err := ioutil.TempFile("", fmt.Sprintf("pcopytest.%s.*.crt", t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certFile.Write([]byte(cert)); err != nil {
		t.Fatal(err)
	}
	defer certFile.Close()

	config.ClipboardDir, err = ioutil.TempDir("", fmt.Sprintf("pcopytest.%s.*.clipdir", t.Name()))
	if err != nil {
		t.Fatal(err)
	}

	config.ServerAddr = "localhost:12345"
	config.ListenAddr = ":12345"
	config.KeyFile = keyFile.Name()
	config.CertFile = certFile.Name()

	return config
}

func cleanupTestConfig(config *Config) {
	if !strings.HasPrefix(config.ClipboardDir, "/tmp/pcopytest") {
		panic(fmt.Errorf("sanity check failed: clipboard dir not in /tmp: %s", config.ClipboardDir))
	}

	os.Remove(config.KeyFile)
	os.Remove(config.CertFile)
	os.RemoveAll(config.ClipboardDir)
}
