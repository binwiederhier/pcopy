package main

import (
	"heckel.io/pcopy"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_JoinAndList(t *testing.T) {
	_, config := newTestConfig(t)
	serverRouter := startTestServerRouter(t, config)
	defer serverRouter.Stop()

	waitForPortUp(t, "12345")

	configDir := t.TempDir()
	os.Setenv(pcopy.EnvConfigDir, configDir)

	app, _, _, stderr := newTestApp()
	if err := runApp(app, "pcopy", "join", "localhost:12345"); err != nil {
		t.Fatal(err)
	}

	assertStrContains(t, stderr.String(), "Successfully joined clipboard, config written to")
	assertFileExist(t, filepath.Join(configDir, "default.conf"))

	stderr.Reset()
	if err := runApp(app, "pcopy", "list"); err != nil {
		t.Fatal(err)
	}
	assertStrContains(t, stderr.String(), "default")
	assertStrContains(t, stderr.String(), "localhost:12345")
}
