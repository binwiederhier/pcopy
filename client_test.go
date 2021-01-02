package pcopy

import (
	"archive/zip"
	"bytes"
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
	config := newConfig()
	client, server := newTestClientAndServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/default" {
			t.Fatalf("expected path %s, got %s", "/default", r.URL.Path)
		}
		if body := readAllToString(t, r.Body); body != "something" {
			t.Fatalf("expected body %s, got %s", "something", body)
		}
	}))
	defer server.Close()

	if err := client.Copy(ioutil.NopCloser(strings.NewReader("something")), "default"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CopyWithHMACAuthSuccess(t *testing.T) {
	config := newConfig()
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

	if err := client.Copy(ioutil.NopCloser(strings.NewReader("blabla")), "hi-there"); err != nil {
		t.Fatal(err)
	}
}

func TestClient_CopyFilesSuccess(t *testing.T) {
	config := newConfig()
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
	if err := client.CopyFiles(files, "a-few-files"); err != nil {
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