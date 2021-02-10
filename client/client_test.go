package client

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/server"
	"heckel.io/pcopy/test"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClient_CopyNoAuthSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/default" {
			t.Fatalf("expected path %s, got %s", "/default", r.URL.Path)
		}
		if body := readAllToString(t, r.Body); body != "something" {
			t.Fatalf("expected body %s, got %s", "something", body)
		}
	}))
	defer serv.Close()

	if _, err := client.Copy(ioutil.NopCloser(strings.NewReader("something")), "default", time.Hour, config.FileModeReadWrite, false); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CopyWithHMACAuthSuccess(t *testing.T) {
	conf := config.New()
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check that HMAC header is there, the in-depth tests are in the server package

		if r.URL.Path != "/hi-there" {
			t.Fatalf("expected path %s, got %s", "/hi-there", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "HMAC ") {
			t.Fatalf("expected auth header to have HMAC prefix, got %s", r.Header.Get("Authorization"))
		}
	}))
	defer serv.Close()

	if _, err := client.Copy(ioutil.NopCloser(strings.NewReader("blabla")), "hi-there", time.Hour, config.FileModeReadWrite, false); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CopyFilesSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zipBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		z, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range z.File {
			switch f.Name {
			case "file1":
				test.StrEquals(t, "file content 1", readZipEntryToString(t, f))
			case "dir1/file2":
				test.StrEquals(t, "file content 2", readZipEntryToString(t, f))
			default:
				t.Fatalf("unexpected file in ZIP archive: %s", f.Name)
			}
		}

	}))
	defer serv.Close()

	tempDir := t.TempDir()
	file1 := filepath.Join(tempDir, "/file1")
	dir1 := filepath.Join(tempDir, "/dir1")
	file2 := filepath.Join(dir1, "/file2")
	os.Mkdir(dir1, 0700)
	ioutil.WriteFile(file1, []byte("file content 1"), 0700)
	ioutil.WriteFile(file2, []byte("file content 2"), 0700)

	files := []string{file1, dir1}
	if _, err := client.CopyFiles(files, "a-few-files", time.Hour, config.FileModeReadWrite, false); err != nil {
		t.Fatal(err)
	}
}

func TestClient_PasteNoAuthSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi there what's up"))
	}))
	defer serv.Close()

	var buf bytes.Buffer
	if err := client.Paste(&buf, "default"); err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "hi there what's up", buf.String())
}

func TestClient_PasteFilesSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		zf1, _ := z.Create("file1.txt")
		zf1.Write([]byte("this is file 1"))
		zf2, _ := z.Create("dir1/file2.txt")
		zf2.Write([]byte("this is file 2"))
		z.Close()
		w.Write(buf.Bytes())
	}))
	defer serv.Close()

	tmpDir := t.TempDir()
	err := client.PasteFiles(tmpDir, "default")
	if err != nil {
		t.Fatal(err)
	}
	f1, err := ioutil.ReadFile(filepath.Join(tmpDir, "file1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f2, err := ioutil.ReadFile(filepath.Join(tmpDir, "dir1/file2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "this is file 1", string(f1))
	test.StrEquals(t, "this is file 2", string(f2))
}

func TestClient_PasteFilesFailure(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not a zip file"))
	}))
	defer serv.Close()

	tmpDir := t.TempDir()
	err := client.PasteFiles(tmpDir, "default")
	if err == nil {
		t.Fatalf("expected error, got no error")
	}
}

func TestClient_PasteNoAuthNotFound(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer serv.Close()

	var buf bytes.Buffer
	var httpErr *server.ErrHTTP
	err := client.Paste(&buf, "default")
	if err == nil {
		t.Fatalf("expected errHTTPNotOK, got no error")
	} else if !errors.As(err, &httpErr) {
		t.Fatal(err)
	}
}

func TestClient_PasteWithCertFile(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some response"))
	}))
	defer serv.Close()
	client.httpClient = nil // We want to use the cert file on disk, and not the mock HTTP client

	conf.CertFile = filepath.Join(t.TempDir(), "server.crt")
	pemCert, _ := crypto.EncodeCert(serv.Certificate())
	ioutil.WriteFile(conf.CertFile, pemCert, 0700)

	var buf bytes.Buffer
	err := client.Paste(&buf, "default")
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "some response", buf.String())
}

func TestClient_ServerInfoSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&server.HTTPResponseServerInfo{
			ServerAddr: "hi-there.com",
			Salt:       "aSBhbSBiYXNlNjQ=",
		})
	}))
	defer serv.Close()

	info, err := client.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "hi-there.com", info.ServerAddr)
	test.BytesEquals(t, []byte("i am base64"), info.Salt)
	test.BytesEquals(t, serv.Certificate().Raw, info.Cert.Raw)
}

func TestClient_InfoFailed(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid response"))
	}))
	defer serv.Close()

	_, err := client.ServerInfo()
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestClient_FileInfoSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		test.StrEquals(t, http.MethodHead, r.Method)
		test.StrEquals(t, "/hi.txt", r.RequestURI)
		w.Header().Set(server.HeaderFile, "hi.txt")
		w.Header().Set(server.HeaderURL, "https://sup.com/hi.txt")
		w.Header().Set(server.HeaderExpires, "1611323111")
		w.Header().Set(server.HeaderTTL, "360")
		w.Header().Set(server.HeaderCurl, "curl https://sup.com/hi.txt")
	}))
	defer serv.Close()

	info, err := client.FileInfo("hi.txt")
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "hi.txt", info.File)
	test.StrEquals(t, "https://sup.com/hi.txt", info.URL)
	test.Int64Equals(t, 1611323111, info.Expires.Unix())
	test.Int64Equals(t, 360, int64(info.TTL.Seconds()))
	test.StrEquals(t, "curl https://sup.com/hi.txt", info.Curl)
}

func TestClient_ReserveSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		test.StrEquals(t, http.MethodPut, r.Method)
		test.StrEquals(t, "1", r.Header.Get(server.HeaderReserve))
		w.Header().Set(server.HeaderFile, "hi.txt")
		w.Header().Set(server.HeaderURL, "https://sup.com/hi.txt")
		w.Header().Set(server.HeaderExpires, "1611323111")
		w.Header().Set(server.HeaderTTL, "360")
		w.Header().Set(server.HeaderCurl, "curl https://sup.com/hi.txt")
	}))
	defer serv.Close()

	info, err := client.Reserve("hi.txt")
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "hi.txt", info.File)
	test.StrEquals(t, "https://sup.com/hi.txt", info.URL)
	test.Int64Equals(t, 1611323111, info.Expires.Unix())
	test.Int64Equals(t, 360, int64(info.TTL.Seconds()))
	test.StrEquals(t, "curl https://sup.com/hi.txt", info.Curl)
}

// TODO add TestReserveFailureTimeout

func TestClient_VerifyWithPinnedCertNoAuthSuccess(t *testing.T) {
	conf := config.New()
	client, serv := newTestClientAndServer(t, conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer serv.Close()

	// Unset, we don't want to override the HTTP client for this test.
	// Instead, pass the certs in the Verify function.
	client.httpClient = nil

	if err := client.Verify(serv.Certificate(), nil); err != nil {
		t.Fatal(err)
	}
}

func newTestClientAndServer(t *testing.T, conf *config.Config, handler http.Handler) (*Client, *httptest.Server) {
	serv := httptest.NewTLSServer(handler)
	conf.ServerAddr = config.ExpandServerAddr(serv.URL)

	client, err := NewClient(conf)
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient = serv.Client() // Inject test client

	return client, serv
}

func readAllToString(t *testing.T, reader io.Reader) string {
	v, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(v)
}

func readZipEntryToString(t *testing.T, f *zip.File) string {
	r, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	return readAllToString(t, r)
}
