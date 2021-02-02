package server

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func TestServer_NewServerInvalidListenAddr(t *testing.T) {
	conf := config.New()
	conf.ListenHTTPS = ""
	_, err := NewServer(conf)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_NewServerInvalidKeyFile(t *testing.T) {
	conf := config.New()
	conf.KeyFile = ""
	conf.CertFile = "something"
	_, err := NewServer(conf)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_NewServerInvalidCertFile(t *testing.T) {
	conf := config.New()
	conf.KeyFile = "something"
	conf.CertFile = ""
	_, err := NewServer(conf)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestServer_HandleInfoUnprotected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.Handle(rr, req)

	test.Response(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":""}`)
}

func TestServer_HandleVerify(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/verify", nil)
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
}

func TestServer_HandleInfoProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = &crypto.Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/info", nil)
	server.Handle(rr, req)

	test.Response(t, rr, http.StatusOK, `{"serverAddr":"localhost:12345","salt":"c29tZSBzYWx0"}`)
}

func TestServer_HandleDoesNotExist(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/some path that can't be a clipboard id", nil)
	server.Handle(rr, req)

	test.Status(t, rr, http.StatusNotFound)
}

func TestServer_HandleCurlRoot(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/1.2.3")
	server.Handle(rr, req)

	test.StrContains(t, rr.Body.String(), "This is is the curl-endpoint for pcopy")
}

func TestServer_HandleWebRoot(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{} // Pretend that this is TLS, so we don't redirect
	server.Handle(rr, req)

	test.Status(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Fatalf("expected html, got: %s", rr.Body.String())
	}
}

func TestServer_HandleWebRootRedirectHTTPS(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.ListenHTTP = ":9876"
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "localhost"
	server.Handle(rr, req)

	test.Status(t, rr, http.StatusFound)
	test.StrEquals(t, "https://localhost:12345/", rr.Header().Get("Location"))
}

func TestServer_HandleWebStaticResource(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/static/js/app.js", nil)
	server.Handle(rr, req)

	test.Status(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "getElementById") {
		t.Fatalf("expected js, got: %s", rr.Body.String())
	}
}

func TestServer_HandleWebFavicon(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/favicon.ico", nil)
	server.Handle(rr, req)

	test.Status(t, rr, http.StatusOK)
	test.BytesEquals(t, []byte{0x00, 0x00, 0x01, 0x00}, rr.Body.Bytes()[:4]) // .ico magic bytes
}

func TestServer_HandleClipboardGetExists(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	file := filepath.Join(conf.ClipboardDir, "this-exists")
	metafile := filepath.Join(conf.ClipboardDir, "this-exists:meta")
	ioutil.WriteFile(file, []byte("hi there"), 0700)
	ioutil.WriteFile(metafile, []byte("{}"), 0700)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists", nil)
	server.Handle(rr, req)
	test.Response(t, rr, http.StatusOK, "hi there")
}

func TestServer_HandleClipboardGetExistsWithAuthParam(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = &crypto.Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, conf)

	file := filepath.Join(conf.ClipboardDir, "this-exists-again")
	metafile := filepath.Join(conf.ClipboardDir, "this-exists-again:meta")
	ioutil.WriteFile(file, []byte("hi there again"), 0700)
	ioutil.WriteFile(metafile, []byte("{}"), 0700)

	hmac, _ := crypto.GenerateAuthHMAC(conf.Key.Bytes, "GET", "/this-exists-again", time.Minute)
	hmacOverrideParam := base64.StdEncoding.EncodeToString([]byte(hmac))

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists-again?a="+hmacOverrideParam, nil)
	server.Handle(rr, req)
	test.Response(t, rr, http.StatusOK, "hi there again")
}

func TestServer_HandleClipboardGetExistsWithAuthParamFailure(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = &crypto.Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	server := newTestServer(t, conf)

	hmacOverrideParam := base64.StdEncoding.EncodeToString([]byte("invalid auth"))

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-exists-again?a=invalid"+hmacOverrideParam, nil)
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusUnauthorized)
}

func TestServer_HandleClipboardGetDoesntExist(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/this-does-not-exist", nil)
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusNotFound)
}

func TestServer_HandleClipboardPut(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	content := "this is a new thing"
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/new-thing", strings.NewReader(content))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "new-thing", content)
}

func TestServer_HandleClipboardPutRandom(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/", strings.NewReader("this is a thing"))
	server.Handle(rr, req)

	test.Status(t, rr, http.StatusOK)

	test.Int64Equals(t, 10, int64(len(rr.Header().Get("X-File"))))
	test.StrEquals(t, fmt.Sprintf("%d", 3600*24*7), rr.Header().Get("X-TTL"))
	clipboardtest.Content(t, conf, rr.Header().Get("X-File"), "this is a thing")
}

func TestServer_HandleClipboardPutUntilLimitReached(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.LimitPUTBurst = 2
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/", strings.NewReader("this is a thing"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/", strings.NewReader("this is a another thing"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/", strings.NewReader("this is a yet another thing"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusTooManyRequests)
}

func TestServer_HandleWebRootGetUntilLimitReached(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.LimitGETBurst = 10
	conf.LimitGET = rate.Every(100 * time.Millisecond)
	server := newTestServer(t, conf)

	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{} // Pretend that this is TLS, so we don't redirect
		server.Handle(rr, req)
		test.Status(t, rr, http.StatusOK)
	}

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{} // Pretend that this is TLS, so we don't redirect
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusTooManyRequests)

	time.Sleep(200 * time.Millisecond)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{} // Pretend that this is TLS, so we don't redirect
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
}

func TestServer_handleClipboardClipboardPutInvalidId(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/../invalid-id", strings.NewReader("hi"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusBadRequest)
	clipboardtest.NotExist(t, conf, "/../invalid-id")
}

func TestServer_HandleClipboardPutGetSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/you-cant-always?t=4d", strings.NewReader("get what you want"))
	server.Handle(rr, req)

	ttl, _ := strconv.Atoi(rr.Header().Get("X-TTL"))
	expires, _ := strconv.Atoi(rr.Header().Get("X-Expires"))

	test.Status(t, rr, http.StatusOK)
	test.StrEquals(t, "you-cant-always", rr.Header().Get("X-File"))
	test.StrEquals(t, "https://localhost:12345/you-cant-always", rr.Header().Get("X-URL"))
	test.StrContains(t, rr.Header().Get("X-Curl"), "https://localhost:12345/you-cant-always")
	test.StrContains(t, rr.Header().Get("X-Curl"), "--pinnedpubkey")
	test.Int64Equals(t, int64(time.Hour*24*4), int64(time.Second*time.Duration(ttl)))
	test.BoolEquals(t, true, time.Until(time.Unix(int64(expires), 0)) <= 24*4*time.Hour)
	test.StrContains(t, rr.Body.String(), "https://localhost:12345/you-cant-always")
	test.StrContains(t, rr.Body.String(), "Direct link (valid for 4d")
	test.StrContains(t, rr.Body.String(), "--pinnedpubkey")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/you-cant-always", nil)
	server.Handle(rr, req)
	test.Response(t, rr, http.StatusOK, "get what you want")
}

func TestServer_HandleClipboardPutWithJsonOutputSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/you-cant-always?f=json", strings.NewReader("get what you want"))
	req.Header.Set("X-TTL", "2m")
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)

	var info httpResponseFileInfo
	json.NewDecoder(rr.Body).Decode(&info)
	test.StrEquals(t, "you-cant-always", info.File)
	test.StrEquals(t, "https://localhost:12345/you-cant-always", info.URL)
	test.StrContains(t, info.Curl, "https://localhost:12345/you-cant-always")
	test.StrContains(t, info.Curl, "--pinnedpubkey")
	test.Int64Equals(t, int64(time.Minute*2), int64(time.Second*time.Duration(info.TTL)))
	test.BoolEquals(t, true, time.Until(time.Unix(info.Expires, 0)) <= 2*time.Minute)
}

func TestServer_HandleClipboardPutWithTooLargeTTL(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.FileExpireAfter = time.Hour
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/too-large-ttl?t=10d", nil)
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)

	ttl, _ := strconv.Atoi(rr.Header().Get("X-TTL")) // TODO X-TTL is inconsistent: request expects a human format, response is seconds
	test.Int64Equals(t, int64(time.Hour), int64(time.Second*time.Duration(ttl)))
}

func TestServer_HandleClipboardPutLargeFailed(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.FileSizeLimit = 10 // bytes
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/too-large", strings.NewReader("more than 10 bytes"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusRequestEntityTooLarge)
	clipboardtest.NotExist(t, conf, "too-large")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/too-large", nil)
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusNotFound)
}

func TestServer_HandleClipboardPutManySmallFailed(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.ClipboardCountLimit = 2
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("lalala"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file1", "lalala")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file2", "another one")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file3", strings.NewReader("yet another one"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusTooManyRequests)
	clipboardtest.NotExist(t, conf, "file3")
}

func TestServer_HandleClipboardPutManySmallOverwriteSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.ClipboardCountLimit = 2
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("lalala"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file1", "lalala")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file2", "another one")

	// Overwrite file 2 should succeed
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("overwriting file 2"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file2", "overwriting file 2")
}

func TestServer_HandleClipboardPutOverwriteFailure(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.FileModesAllowed = []string{config.FileModeReadOnly}
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file2", "another one")

	// Overwrite file 2 should fail
	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("overwriting file 2 fails"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusMethodNotAllowed)
}

func TestServer_HandleClipboardPutReadWriteFailure(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.FileModesAllowed = []string{config.FileModeReadOnly}
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file2?m=rw", strings.NewReader("another one"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusBadRequest)
}

func TestServer_HandleClipboardPutReadOnlyDisallowOverwriteSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	req.Header.Set("X-Mode", "ro")
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("another one"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusMethodNotAllowed)
}

func TestServer_HandleClipboardPutTotalSizeLimitFailed(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.ClipboardSizeLimit = 10
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/file1", strings.NewReader("7 bytes"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "file1", "7 bytes")

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("PUT", "/file2", strings.NewReader("4 bytes"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusRequestEntityTooLarge)
	clipboardtest.NotExist(t, conf, "file2")
}

func TestServer_HandleClipboardPutStreamSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	payload := string(bytes.Repeat([]byte("this is a 60 byte long string that's being repeated 99 times"), 99))

	go func() {
		rr1 := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/file1?s=1", strings.NewReader(payload))
		server.Handle(rr1, req)
		test.Status(t, rr1, http.StatusOK)
	}()

	time.Sleep(100 * time.Millisecond)

	filename := filepath.Join(conf.ClipboardDir, "file1")
	stat, _ := os.Stat(filename)
	test.BoolEquals(t, true, stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/file1", nil)
	server.Handle(rr, req)
	test.Response(t, rr, http.StatusOK, payload)

	stat, _ = os.Stat(filename)
	test.BoolEquals(t, true, stat == nil)
}

// TODO add tests to include :meta files

func TestServer_HandleClipboardPutStreamWithReserveSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	payload := string(bytes.Repeat([]byte("this is a 60 byte long string that's being repeated 10 times"), 10))

	go func() {
		// Reserve
		rr1 := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/file1?r=1", nil)
		server.Handle(rr1, req)
		test.Status(t, rr1, http.StatusOK)
		clipboardtest.Content(t, conf, "file1", "")

		// Stream
		rr1 = httptest.NewRecorder()
		req, _ = http.NewRequest("PUT", "/file1?s=1", strings.NewReader(payload))
		server.Handle(rr1, req)
		test.Status(t, rr1, http.StatusOK)
	}()

	time.Sleep(100 * time.Millisecond)

	filename := filepath.Join(conf.ClipboardDir, "file1")
	stat, _ := os.Stat(filename)
	test.BoolEquals(t, true, stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/file1", nil)
	server.Handle(rr, req)
	test.Response(t, rr, http.StatusOK, payload)

	stat, _ = os.Stat(filename)
	test.BoolEquals(t, true, stat == nil)
}

func TestServer_HandleClipboardHeadSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/abc", strings.NewReader("this is a thing"))
	server.Handle(rr, req)

	rr = httptest.NewRecorder()
	req, _ = http.NewRequest("HEAD", "/abc", nil)
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)

	test.StrEquals(t, "abc", rr.Header().Get("X-File"))
	test.StrEquals(t, "https://"+conf.ServerAddr+"/abc", rr.Header().Get("X-URL"))
	test.StrContains(t, rr.Header().Get("X-Curl"), "--pinnedpubkey")
}

func TestServer_AuthorizeSuccessUnprotected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeFailureMissingProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeBasicSuccessProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x:some password")))
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeBasicFailureProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x:incorrect password")))
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacSuccessProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := crypto.GenerateAuthHMAC(conf.Key.Bytes, "GET", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthorizeHmacFailureWrongPathProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := crypto.GenerateAuthHMAC(conf.Key.Bytes, "GET", "/wrong-path", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacFailureWrongMethodProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := crypto.GenerateAuthHMAC(conf.Key.Bytes, "PUT", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_AuthorizeHmacFailureWrongKeyProtected(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	server := newTestServer(t, conf)

	req, _ := http.NewRequest("GET", "/", nil)
	hmac, _ := crypto.GenerateAuthHMAC(make([]byte, 32), "GET", "/", time.Minute)
	req.Header.Set("Authorization", hmac)
	if err := server.authorize(req); err != ErrHTTPUnauthorized {
		t.Fatalf("expected invalid auth, got %#v", err)
	}
}

func TestServer_ExpireSuccess(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.FileExpireAfter = time.Second
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/new-thing", strings.NewReader("something"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusOK)
	clipboardtest.Content(t, conf, "new-thing", "something")

	time.Sleep(1050 * time.Millisecond)
	server.updateStatsAndExpire()
	clipboardtest.NotExist(t, conf, "new-thing")
}

func TestServer_ReservedWordsFailure(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	server := newTestServer(t, conf)

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/robots.txt", strings.NewReader("something"))
	server.Handle(rr, req)
	test.Status(t, rr, http.StatusBadRequest)
}

func TestServer_StartStopManager(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.ManagerInterval = 100 * time.Millisecond
	server := newTestServer(t, conf)

	server.StartManager()
	time.Sleep(10 * time.Millisecond)

	server.clipboard.WriteFile("testfile", io.NopCloser(strings.NewReader("this is a test")))
	server.clipboard.WriteMeta("testfile", config.FileModeReadWrite, time.Now().Unix())

	cf, _ := server.clipboard.Stat("testfile")
	test.StrEquals(t, "testfile", cf.ID)

	time.Sleep(100 * time.Millisecond)
	cf, _ = server.clipboard.Stat("testfile")
	if cf != nil {
		t.Fatalf("expected testfile to have disappeared, but it did not")
	}

	server.StopManager()
	server.clipboard.WriteFile("testfile2", io.NopCloser(strings.NewReader("this is another test")))
	server.clipboard.WriteMeta("testfile2", config.FileModeReadWrite, time.Now().Unix())

	time.Sleep(110 * time.Millisecond)
	cf, _ = server.clipboard.Stat("testfile2")
	test.StrEquals(t, "testfile2", cf.ID)
}

func newTestServer(t *testing.T, config *config.Config) *Server {
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}
