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

func TestServer_NewServerInvalidListenAddr(t *testing.T) {
	config := newConfig()
	config.ListenAddr = ""
	_, err := newServer(config)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_NewServerInvalidKeyFile(t *testing.T) {
	config := newConfig()
	config.KeyFile = ""
	config.CertFile = "something"
	_, err := newServer(config)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_NewServerInvalidCertFile(t *testing.T) {
	config := newConfig()
	config.KeyFile = "something"
	config.CertFile = ""
	_, err := newServer(config)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_HandleInfoUnprotected(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handle(rr, req)

	assertResponse(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":""}`)
}

func TestServer_HandleInfoProtected(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.handle(rr, req)

	assertResponse(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":"c29tZSBzYWx0"}`)
}

func TestServer_HandleDoesNotExist(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/some path that can't be a clipboard id", nil)
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusNotFound)
}

func TestServer_HandleWebRootNoGUI(t *testing.T) {
	config := newTestServerConfig(t)
	config.WebUI = false
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
}

func TestServer_HandleWebRootWithGUI(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Fatalf("expected html, got: %s", rr.Body.String())
	}
}

func TestServer_HandleWebStaticResourceWithGUI(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/static/js/app.js", nil)
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "getElementById") {
		t.Fatalf("expected js, got: %s", rr.Body.String())
	}
}

func TestServer_HandleClipboardGetExists(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	filename := filepath.Join(config.ClipboardDir, "this-exists")
	if err := ioutil.WriteFile(filename, []byte("hi there"), 0700); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists", nil)
	server.handle(rr, req)
	assertResponse(t, rr, http.StatusOK, "hi there")
}

func TestServer_HandleClipboardGetExistsWithAuthParam(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	filename := filepath.Join(config.ClipboardDir, "this-exists-again")
	if err := ioutil.WriteFile(filename, []byte("hi there again"), 0700); err != nil {
		t.Fatal(err)
	}

	hmac, _ := GenerateAuthHMAC(config.Key.Bytes, "GET", "/this-exists-again", time.Minute)
	hmacOverrideParam := base64.StdEncoding.EncodeToString([]byte(hmac))

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists-again?a="+hmacOverrideParam, nil)
	server.handle(rr, req)
	assertResponse(t, rr, http.StatusOK, "hi there again")
}

func TestServer_HandleClipboardGetExistsWithAuthParamFailure(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	hmacOverrideParam := base64.StdEncoding.EncodeToString([]byte("invalid auth"))

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists-again?a=invalid"+hmacOverrideParam, nil)
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestServer_HandleClipboardGetDoesntExist(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-does-not-exist", nil)
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestServer_HandleClipboardPut(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	content := "this is a new thing"
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/new-thing", strings.NewReader(content))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "new-thing", content)
}

func TestServer_handleClipboardClipboardPutInvalidId(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/../invalid-id", strings.NewReader("hi"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "/../invalid-id")
}

func TestServer_HandleClipboardPutGet(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/you-cant-always", strings.NewReader("get what you want"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/you-cant-always", nil)
	server.handle(rr, req)
	assertResponse(t, rr, http.StatusOK, "get what you want")
}

func TestServer_HandleClipboardPutLargeFailed(t *testing.T) {
	config := newTestServerConfig(t)
	config.FileSizeLimit = 10 // bytes
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/too-large", strings.NewReader("more than 10 bytes"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "too-large")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/too-large", nil)
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestServer_HandleClipboardPutManySmallFailed(t *testing.T) {
	config := newTestServerConfig(t)
	config.ClipboardCountLimit = 2
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("lalala"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file1", "lalala")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "another one")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file3", strings.NewReader("yet another one"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusTooManyRequests)
	assertNotExists(t, config, "file3")
}

func TestServer_HandleClipboardPutManySmallOverwriteSuccess(t *testing.T) {
	config := newTestServerConfig(t)
	config.ClipboardCountLimit = 2
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("lalala"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file1", "lalala")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "another one")

	// Overwrite file 2 should succeed
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("overwriting file 2"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "overwriting file 2")
}

func TestServer_HandleClipboardPutTotalSizeLimitFailed(t *testing.T) {
	config := newTestServerConfig(t)
	config.ClipboardSizeLimit = 10
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("7 bytes"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file1", "7 bytes")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("4 bytes"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
	assertNotExists(t, config, "file2")
}

func TestServer_HandleJoinWithKeySuccess(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/join", nil)
	hmac, _ := GenerateAuthHMAC(config.Key.Bytes, "GET", "/join", time.Minute)
	req.Header.Set("Authorization", hmac)
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "#!/bin/sh") {
		t.Fatalf("expected shell code, got: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "PCOPY_KEY=") {
		t.Fatalf("expected PCOPY_KEY env, got: %s", rr.Body.String())
	}
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
	if err := server.authorize(req); err != errHTTPUnauthorized {
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
	if err := server.authorize(req); err != errHTTPUnauthorized {
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
	if err := server.authorize(req); err != errHTTPUnauthorized {
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
	if err := server.authorize(req); err != errHTTPUnauthorized {
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
	if err := server.authorize(req); err != errHTTPUnauthorized {
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
