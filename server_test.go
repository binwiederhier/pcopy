package pcopy

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func TestServer_InfoUnprotected(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handleInfo(rr, req)

	assertResponse(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":""}`)
}

func TestServer_InfoProtected(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handleInfo(rr, req)

	assertResponse(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":"c29tZSBzYWx0"}`)
}

func TestServer_DefaultWebRootNoGUI(t *testing.T) {
	config := newTestServerConfig(t)
	config.WebUI = false
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	server.handleDefault(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
}

func TestServer_DefaultWebRootWithGUI(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
}

func TestServer_DefaultClipboardGetExists(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	filename := filepath.Join(config.ClipboardDir, "this-exists")
	if err := ioutil.WriteFile(filename, []byte("hi there"), 0700); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists", nil)
	server.handleDefault(rr, req)
	assertResponse(t, rr, http.StatusOK, "hi there")
}

func TestServer_DefaultClipboardGetDoesntExist(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-does-not-exist", nil)
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestServer_DefaultClipboardPut(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	content := "this is a new thing"
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/new-thing", strings.NewReader(content))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "new-thing", content)
}

func TestServer_DefaultClipboardPutInvalidId(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/../invalid-id", strings.NewReader("hi"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "/../invalid-id")
}

func TestServer_DefaultClipboardPutGet(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/you-cant-always", strings.NewReader("get what you want"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/you-cant-always", nil)
	server.handleDefault(rr, req)
	assertResponse(t, rr, http.StatusOK, "get what you want")
}

func TestServer_DefaultClipboardPutLargeFailed(t *testing.T) {
	config := newTestServerConfig(t)
	config.FileSizeLimit = 10 // bytes
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/too-large", strings.NewReader("more than 10 bytes"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "too-large")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/too-large", nil)
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestServer_DefaultClipboardPutManySmallFailed(t *testing.T) {
	config := newTestServerConfig(t)
	config.ClipboardCountLimit = 2
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("lalala"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file1", "lalala")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "another one")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file3", strings.NewReader("yet another one"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "file3")
}

func TestServer_DefaultClipboardPutManySmallOverwriteSuccess(t *testing.T) {
	config := newTestServerConfig(t)
	config.ClipboardCountLimit = 2
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("lalala"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file1", "lalala")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "another one")

	// Overwrite file 2 should succeed
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("overwriting file 2"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "overwriting file 2")
}

func TestServer_DefaultClipboardPutTotalSizeLimitFailed(t *testing.T) {
	config := newTestServerConfig(t)
	config.ClipboardSizeLimit = 10
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("7 bytes"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file1", "7 bytes")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("4 bytes"))
	server.handleDefault(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "file2")
}

func TestServer_AuthorizeSuccessUnprotected(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeFailureMissingProtected(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeBasicSuccessProtected(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x:some password")))
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeBasicFailureProtected(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x:incorrect password")))
	if err := server.authorize(req); err != errInvalidAuth {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacSuccessProtected(t *testing.T) {
	config := newTestServerConfig(t)
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
	config := newTestServerConfig(t)
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
	config := newTestServerConfig(t)
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
	config := newTestServerConfig(t)
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

func newTestServerConfig(t *testing.T) *Config {
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

func assertNotExists(t *testing.T, config *Config, id string) {
	filename := filepath.Join(config.ClipboardDir, id)
	if _, err := os.Stat(filename); err == nil {
		t.Fatalf("expected file %s to not exist, but it does", filename)
	}
}

func assertFileContent(t *testing.T, config *Config, id string, content string) {
	filename := filepath.Join(config.ClipboardDir, id)
	actualContent, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualContent) != content {
		t.Fatalf("expected %s, got %s", content, actualContent)
	}
}
