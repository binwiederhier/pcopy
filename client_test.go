package pcopy

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClient_CopyNoAuthSuccess(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/default" {
			t.Fatalf("expected path %s, got %s", "/default", r.URL.Path)
		}
		if body := readAllToString(t, r.Body); body != "something" {
			t.Fatalf("expected body %s, got %s", "something", body)
		}
	}))
	defer server.Close()

	if err := client.Copy(ioutil.NopCloser(strings.NewReader("something")), "default", false); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CopyWithHMACAuthSuccess(t *testing.T) {
	config := NewConfig()
	config.Key = DeriveKey([]byte("some password"), []byte("some salt"))
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check that HMAC header is there, the in-depth tests are in the server package

		if r.URL.Path != "/hi-there" {
			t.Fatalf("expected path %s, got %s", "/hi-there", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "HMAC ") {
			t.Fatalf("expected auth header to have HMAC prefix, got %s", r.Header.Get("Authorization"))
		}
	}))
	defer server.Close()

	if err := client.Copy(ioutil.NopCloser(strings.NewReader("blabla")), "hi-there", false); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CopyFilesSuccess(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				assertStrEquals(t, "file content 1", readZipEntryToString(t, f))
			case "dir1/file2":
				assertStrEquals(t, "file content 2", readZipEntryToString(t, f))
			default:
				t.Fatalf("unexpected file in ZIP archive: %s", f.Name)
			}
		}

	}))
	defer server.Close()

	tempDir := t.TempDir()
	file1 := filepath.Join(tempDir, "/file1")
	dir1 := filepath.Join(tempDir, "/dir1")
	file2 := filepath.Join(dir1, "/file2")
	os.Mkdir(dir1, 0700)
	ioutil.WriteFile(file1, []byte("file content 1"), 0700)
	ioutil.WriteFile(file2, []byte("file content 2"), 0700)

	files := []string{file1, dir1}
	if err := client.CopyFiles(files, "a-few-files", false); err != nil {
		t.Fatal(err)
	}
}

func TestClient_PasteNoAuthSuccess(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi there what's up"))
	}))
	defer server.Close()

	var buf bytes.Buffer
	if err := client.Paste(&buf, "default"); err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "hi there what's up", buf.String())
}

func TestClient_PasteFilesSuccess(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		zf1, _ := z.Create("file1.txt")
		zf1.Write([]byte("this is file 1"))
		zf2, _ := z.Create("dir1/file2.txt")
		zf2.Write([]byte("this is file 2"))
		z.Close()
		w.Write(buf.Bytes())
	}))
	defer server.Close()

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
	assertStrEquals(t, "this is file 1", string(f1))
	assertStrEquals(t, "this is file 2", string(f2))
}

func TestClient_PasteFilesFailure(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not a zip file"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	err := client.PasteFiles(tmpDir, "default")
	if err == nil {
		t.Fatalf("expected error, got no error")
	}
}

func TestClient_PasteNoAuthNotFound(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	var buf bytes.Buffer
	var httpErr *errHTTPNotOK
	err := client.Paste(&buf, "default")
	if err == nil {
		t.Fatalf("expected errHTTPNotOK, got no error")
	} else if !errors.As(err, &httpErr) {
		t.Fatal(err)
	}
}

func TestClient_InfoSuccess(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&infoResponse{
			ServerAddr: "hi-there.com",
			Salt:       "aSBhbSBiYXNlNjQ=",
		})
	}))
	defer server.Close()

	info, err := client.Info()
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "hi-there.com", info.ServerAddr)
	assertBytesEquals(t, []byte("i am base64"), info.Salt)
	assertBytesEquals(t, server.Certificate().Raw, info.Cert.Raw)
}

func TestClient_InfoFailed(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid response"))
	}))
	defer server.Close()

	_, err := client.Info()
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestClient_PasteWithCertFile(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some response"))
	}))
	defer server.Close()
	client.httpClient = nil // We want to use the cert file on disk, and not the mock HTTP client

	config.CertFile = filepath.Join(t.TempDir(), "server.crt")
	pemCert, _ := EncodeCert(server.Certificate())
	ioutil.WriteFile(config.CertFile, pemCert, 0700)

	var buf bytes.Buffer
	err := client.Paste(&buf, "default")
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "some response", buf.String())
}

func TestClient_VerifyWithPinnedCertNoAuthSuccess(t *testing.T) {
	config := NewConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Unset, we don't want to override the HTTP client for this test.
	// Instead, pass the certs in the Verify function.
	client.httpClient = nil

	if err := client.Verify(server.Certificate(), nil); err != nil {
		t.Fatal(err)
	}
}

func newTestClientAndServer(t *testing.T, config *Config, handler http.Handler) (*Client, *httptest.Server) {
	server := httptest.NewTLSServer(handler)
	uri, err := url.ParseRequestURI(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	config.ServerAddr = uri.Host

	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient = server.Client() // Inject test client

	return client, server
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

func assertInt64Equals(t *testing.T, expected int64, actual int64) {
	if actual != expected {
		t.Fatalf("expected %d, got %d", expected, actual)
	}
}

func assertBoolEquals(t *testing.T, expected bool, actual bool) {
	if actual != expected {
		t.Fatalf("expected %t, got %t", expected, actual)
	}
}

func assertBytesEquals(t *testing.T, expected []byte, actual []byte) {
	if !bytes.Equal(actual, expected) {
		t.Fatalf("expected %x, got %x", expected, actual)
	}
}
