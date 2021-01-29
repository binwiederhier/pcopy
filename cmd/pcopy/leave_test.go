package main

import (
	"heckel.io/pcopy"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_LeaveDefault(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "default.conf"), []byte("dummy config file"), 0600)
	os.WriteFile(filepath.Join(dir, "default.crt"), []byte("dummy cert"), 0600)

	os.Setenv(pcopy.EnvConfigDir, dir)
	app, _, stdout, _ := newTestApp()
	if err := runApp(app, "pcopy", "leave"); err != nil {
		t.Fatal(err)
	}

	assertStrContains(t, stdout.String(), "Successfully left clipboard 'default'")
	assertFileNotExist(t, filepath.Join(dir, "default.conf"))
	assertFileNotExist(t, filepath.Join(dir, "default.crt"))
	assertFileNotExist(t, filepath.Join(dir, "default.key"))
}

func TestCLI_LeaveCustom(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "clip.conf"), []byte("dummy config file"), 0600)
	os.WriteFile(filepath.Join(dir, "clip.crt"), []byte("dummy cert"), 0600)
	os.WriteFile(filepath.Join(dir, "clip.key"), []byte("dummy key"), 0600)

	os.Setenv(pcopy.EnvConfigDir, dir)
	app, _, stdout, _ := newTestApp()
	if err := runApp(app, "pcopy", "leave", "clip"); err != nil {
		t.Fatal(err)
	}

	assertStrContains(t, stdout.String(), "Successfully left clipboard 'clip'")
	assertFileNotExist(t, filepath.Join(dir, "clip.conf"))
	assertFileNotExist(t, filepath.Join(dir, "clip.crt"))
	assertFileNotExist(t, filepath.Join(dir, "clip.key"))
}
