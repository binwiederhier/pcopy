package cmd

import (
	"encoding/base64"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"heckel.io/pcopy/util"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_JoinAndList(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	serverRouter := startTestServerRouter(t, conf)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "12345")

	configDir := t.TempDir()
	os.Setenv(config.EnvConfigDir, configDir)

	app, _, _, stderr := newTestApp()
	if err := Run(app, "pcopy", "join", "localhost:12345"); err != nil {
		t.Fatal(err)
	}

	test.StrContains(t, stderr.String(), "Successfully joined clipboard, config written to")
	test.FileExist(t, filepath.Join(configDir, "default.conf"))

	stderr.Reset()
	if err := Run(app, "pcopy", "list"); err != nil {
		t.Fatal(err)
	}
	test.StrContains(t, stderr.String(), "default")
	test.StrContains(t, stderr.String(), "localhost:12345")
}

func TestCLI_JoinFailedWithGuessedPorts(t *testing.T) {
	configDir := t.TempDir()
	os.Setenv(config.EnvConfigDir, configDir)
	os.Setenv(util.EnvHTTPClientTimeout, "100ms")

	app, _, _, stderr := newTestApp()
	err := Run(app, "pcopy", "join", "example.com")
	if err == nil {
		t.Fatal("expected join command to fail, but it succeeded")
	}
	test.StrContains(t, stderr.String(), "Joining clipboard at example.com ...")
	test.StrContains(t, err.Error(), "https://example.com")
	test.StrContains(t, err.Error(), "https://example.com:2586")
	test.StrContains(t, err.Error(), "Timeout exceeded")
}

func TestCLI_JoinWithPasswordAndCopyAndPaste(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.Key = crypto.DeriveKey([]byte("some password"), []byte("some salt"))
	serverRouter := startTestServerRouter(t, conf)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "12345")

	configDir := t.TempDir()
	os.Setenv(config.EnvConfigDir, configDir)

	app, stdin, _, stderr := newTestApp()
	stdin.WriteString("some password")

	if err := Run(app, "pcopy", "join", "localhost:12345"); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(filepath.Join(configDir, "default.conf"))
	saltBase64 := base64.StdEncoding.EncodeToString(conf.Key.Salt)

	test.StrContains(t, stderr.String(), "Successfully joined clipboard, config written to")
	test.StrContains(t, string(content), saltBase64)
	test.FileExist(t, filepath.Join(configDir, "default.conf"))
}
