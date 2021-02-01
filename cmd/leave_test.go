package cmd

import (
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/test"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_LeaveDefault(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "default.conf"), []byte("dummy config file"), 0600)
	os.WriteFile(filepath.Join(dir, "default.crt"), []byte("dummy cert"), 0600)

	os.Setenv(config.EnvConfigDir, dir)
	app, _, stdout, _ := newTestApp()
	if err := Run(app, "pcopy", "leave"); err != nil {
		t.Fatal(err)
	}

	test.StrContains(t, stdout.String(), "Successfully left clipboard 'default'")
	test.FileNotExist(t, filepath.Join(dir, "default.conf"))
	test.FileNotExist(t, filepath.Join(dir, "default.crt"))
	test.FileNotExist(t, filepath.Join(dir, "default.key"))
}

func TestCLI_LeaveCustom(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "clip.conf"), []byte("dummy config file"), 0600)
	os.WriteFile(filepath.Join(dir, "clip.crt"), []byte("dummy cert"), 0600)
	os.WriteFile(filepath.Join(dir, "clip.key"), []byte("dummy key"), 0600)

	os.Setenv(config.EnvConfigDir, dir)
	app, _, stdout, _ := newTestApp()
	if err := Run(app, "pcopy", "leave", "clip"); err != nil {
		t.Fatal(err)
	}

	test.StrContains(t, stdout.String(), "Successfully left clipboard 'clip'")
	test.FileNotExist(t, filepath.Join(dir, "clip.conf"))
	test.FileNotExist(t, filepath.Join(dir, "clip.crt"))
	test.FileNotExist(t, filepath.Join(dir, "clip.key"))
}
