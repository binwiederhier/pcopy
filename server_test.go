package pcopy

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServer_InfoUnprotected(t *testing.T) {
	config := newTestConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handleInfo(rr, req)

	assertResponse(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":""}`)
}

func TestServer_InfoProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handleInfo(rr, req)

	assertResponse(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":"c29tZSBzYWx0"}`)
}

func TestServer_DefaultWebRootNoGUI(t *testing.T) {
	config := newTestConfig(t)
	config.WebUI = false
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	server.handleDefault(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
}

func TestServer_DefaultWebRootWithGUI(t *testing.T) {
	config := newTestConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	server.handleDefault(rr, req)

	assertStatus(t, rr, http.StatusOK)
}

func TestServer_AuthorizeSuccessUnprotected(t *testing.T) {
	config := newTestConfig(t)
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeFailureMissingProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeBasicSuccessProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("x:some password")))
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeBasicFailureProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("x:incorrect password")))
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacSuccessProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := GenerateAuthHMAC(config.Key.Bytes, "GET", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeHmacFailureWrongPathProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := GenerateAuthHMAC(config.Key.Bytes, "GET", "/wrong-path", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacFailureWrongMethodProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := GenerateAuthHMAC(config.Key.Bytes, "PUT", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacFailureWrongKeyProtected(t *testing.T) {
	config := newTestConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := GenerateAuthHMAC(make([]byte, config.KeyLenBytes), "GET", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
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
	tempDir := t.TempDir()

	key, cert, err := GenerateKeyAndCert()
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

	config.ServerAddr = "localhost:12345"
	config.ListenAddr = ":12345"
	config.ClipboardDir = clipboardDir
	config.KeyFile = keyFile
	config.CertFile = certFile

	return config
}

func assertResponse(t *testing.T, rr *httptest.ResponseRecorder, status int, body string) {
	assertStatus(t, rr, status)
	assertBody(t, rr, body)
}

func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, status int) {
	if rr.Code != status {
		t.Errorf("unexpected status code: got %v want %v", rr.Code, status)
	}
}

func assertBody(t *testing.T, rr *httptest.ResponseRecorder, body string) {
	if strings.TrimSpace(rr.Body.String()) != strings.TrimSpace(body) {
		t.Errorf("unexpected body: got %v want %v", strings.TrimSpace(rr.Body.String()), strings.TrimSpace(body))
	}
}

