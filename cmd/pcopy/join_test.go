package main

import (
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/test"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_JoinAndList(t *testing.T) {
	_, conf := newTestConfig(t)
	serverRouter := startTestServerRouter(t, conf)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "12345")

	configDir := t.TempDir()
	os.Setenv(config.EnvConfigDir, configDir)

	app, _, _, stderr := newTestApp()
	if err := runApp(app, "pcopy", "join", "localhost:12345"); err != nil {
		t.Fatal(err)
	}

	test.StrContains(t, stderr.String(), "Successfully joined clipboard, config written to")
	test.FileExist(t, filepath.Join(configDir, "default.conf"))

	stderr.Reset()
	if err := runApp(app, "pcopy", "list"); err != nil {
		t.Fatal(err)
	}
	test.StrContains(t, stderr.String(), "default")
	test.StrContains(t, stderr.String(), "localhost:12345")
}
