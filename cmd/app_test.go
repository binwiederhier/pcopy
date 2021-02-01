package cmd

import (
	"bytes"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/server"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// This only contains helpers so far

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func newTestApp() (*cli.App, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	var stdin, stdout, stderr bytes.Buffer
	app := New()
	app.Reader = &stdin
	app.Writer = &stdout
	app.ErrWriter = &stderr
	return app, &stdin, &stdout, &stderr
}

func newTestConfig(t *testing.T) (string, *config.Config) {
	conf := config.New()
	tempDir := t.TempDir()

	key, cert, err := crypto.GenerateKeyAndCert("localhost")
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

	conf.ServerAddr = config.ExpandServerAddr("localhost:12345")
	conf.ListenHTTPS = ":12345"
	conf.ClipboardDir = clipboardDir
	conf.KeyFile = keyFile
	conf.CertFile = certFile

	filename := filepath.Join(tempDir, "config.conf")
	if err := conf.WriteFile(filename); err != nil {
		t.Fatal(err)
	}

	return filename, conf
}

func startTestServerRouter(t *testing.T, config *config.Config) *server.Router {
	router, err := server.NewRouter(config)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := router.Start(); err != nil && err != http.ErrServerClosed {
			panic(err) // 'go vet' complains about 't.Fatal(err)'
		}
	}()
	return router
}
