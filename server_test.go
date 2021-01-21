package pcopy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
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
	config := NewConfig()
	config.ListenHTTPS = ""
	_, err := newServer(config)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_NewServerInvalidKeyFile(t *testing.T) {
	config := NewConfig()
	config.KeyFile = ""
	config.CertFile = "something"
	_, err := newServer(config)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_NewServerInvalidCertFile(t *testing.T) {
	config := NewConfig()
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

func TestServer_HandleVerify(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/verify", nil)
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
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

func TestServer_HandleCurlRoot(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/1.2.3")
	server.handle(rr, req)

	assertStrContains(t, rr.Body.String(), "This is is the curl-endpoint for pcopy")
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
	req.TLS = &tls.ConnectionState{} // No redirect
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Fatalf("expected html, got: %s", rr.Body.String())
	}
}

func TestServer_HandleWebRootRedirectHTTPSWithGUI(t *testing.T) {
	config := newTestServerConfig(t)
	config.ListenHTTP = ":9876"
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "localhost"
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusFound)
	assertStrEquals(t, "https://localhost:12345/", rr.Header().Get("Location"))
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

func TestServer_HandleClipboardPutRandom(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/", strings.NewReader("this is a thing"))
	server.handle(rr, req)

	assertStatus(t, rr, http.StatusOK)

	assertInt64Equals(t, 10, int64(len(rr.Header().Get("X-File"))))
	assertStrEquals(t, fmt.Sprintf("%d", 3600*24*7), rr.Header().Get("X-TTL"))
	assertFileContent(t, config, rr.Header().Get("X-File"), "this is a thing")
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
	assertStatus(t, rr, http.StatusRequestEntityTooLarge)
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

func TestServer_HandleClipboardPutOverwriteFailure(t *testing.T) {
	config := newTestServerConfig(t)
	config.FileModesAllowed = []string{FileModeReadOnly}
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "file2", "another one")

	// Overwrite file 2 should fail
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("overwriting file 2 fails"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusMethodNotAllowed)
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
	assertStatus(t, rr, http.StatusRequestEntityTooLarge)
	assertNotExists(t, config, "file2")
}

func TestServer_HandleClipboardPutStreamSuccess(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	payload := string(bytes.Repeat([]byte("this is a 60 byte long string that's being repeated 99 times"), 99))

	go func() {
		rr1 := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/file1?s=1", strings.NewReader(payload))
		server.handle(rr1, req)
		assertStatus(t, rr1, http.StatusOK)
	}()

	time.Sleep(100 * time.Millisecond)

	filename := filepath.Join(config.ClipboardDir, "file1")
	stat, _ := os.Stat(filename)
	assertBoolEquals(t, true, stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/file1", nil)
	server.handle(rr, req)
	assertResponse(t, rr, http.StatusOK, payload)

	stat, _ = os.Stat(filename)
	assertBoolEquals(t, true, stat == nil)
}

// TODO add tests to include :meta files

func TestServer_HandleClipboardPutStreamWithReserveSuccess(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	payload := string(bytes.Repeat([]byte("this is a 60 byte long string that's being repeated 10 times"), 10))

	go func() {
		// Reserve
		rr1 := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/file1?r=1", nil)
		server.handle(rr1, req)
		assertStatus(t, rr1, http.StatusOK)
		assertFileContent(t, config, "file1", "")

		// Stream
		rr1 = httptest.NewRecorder()
		req, _ = http.NewRequest("PUT", "/file1?s=1", strings.NewReader(payload))
		server.handle(rr1, req)
		assertStatus(t, rr1, http.StatusOK)
	}()

	time.Sleep(100 * time.Millisecond)

	filename := filepath.Join(config.ClipboardDir, "file1")
	stat, _ := os.Stat(filename)
	assertBoolEquals(t, true, stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/file1", nil)
	server.handle(rr, req)
	assertResponse(t, rr, http.StatusOK, payload)

	stat, _ = os.Stat(filename)
	assertBoolEquals(t, true, stat == nil)
}

func TestServer_HandleClipboardHeadSuccess(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/abc", strings.NewReader("this is a thing"))
	server.handle(rr, req)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("HEAD", "/abc", nil)
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)

	assertStrEquals(t, "abc", rr.Header().Get("X-File"))
	assertStrEquals(t, "https://"+config.ServerAddr+"/abc", rr.Header().Get("X-URL"))
	assertStrContains(t, rr.Header().Get("X-Curl"), "--pinnedpubkey")
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
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
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
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
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
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
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
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacFailureWrongKeyProtected(t *testing.T) {
	config := newTestServerConfig(t)
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, config)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := GenerateAuthHMAC(make([]byte, 32), "GET", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_ExpireSuccess(t *testing.T) {
	config := newTestServerConfig(t)
	config.FileExpireAfter = time.Second
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/new-thing", strings.NewReader("something"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusOK)
	assertFileContent(t, config, "new-thing", "something")

	time.Sleep(1050 * time.Millisecond)
	server.updateStatsAndExpire()
	assertNotExists(t, config, "new-thing")
}

func TestServer_ReservedWordsFailure(t *testing.T) {
	config := newTestServerConfig(t)
	server := newTestServer(t, config)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/robots.txt", strings.NewReader("something"))
	server.handle(rr, req)
	assertStatus(t, rr, http.StatusBadRequest)
}

func newTestServer(t *testing.T, config *Config) *server {
	server, err := newServer(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func newTestServerConfig(t *testing.T) *Config {
	config := NewConfig()
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
	config.ListenHTTPS = ":12345"
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
