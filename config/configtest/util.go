package configtest

import (
	"fmt"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func NewTestConfig(t *testing.T) (string, *config.Config) {
	return NewTestConfigWithHostname(t, "localhost")
}

func NewTestConfigWithHostname(t *testing.T, hostname string) (string, *config.Config) {
	conf := config.New()
	tempDir := t.TempDir()

	key, cert, err := crypto.GenerateKeyAndCert(hostname)
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

	conf.ServerAddr = config.ExpandServerAddr(fmt.Sprintf("%s:12345", hostname))
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
