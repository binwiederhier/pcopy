package cmd

import (
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/test"
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_ServeAndJoin(t *testing.T) {
	go func() {
		filename, config := configtest.NewTestConfig(t)
		config.ListenHTTPS = ":18818"
		config.ServerAddr = "https://localhost:18818"
		config.WriteFile(filename)
		app, _, _, _ := newTestApp()
		if err := Run(app, "pcopy", "serve", "-c", filename); err != nil {
			panic(err) // cannot t.Fatal in goroutine
		}
	}()
	test.WaitForPortUp(t, "18818")

	configDir := t.TempDir()
	os.Setenv(config.EnvConfigDir, configDir)
	app, _, _, stderr := newTestApp()
	if err := Run(app, "pcopy", "join", "localhost:18818"); err != nil {
		t.Fatal(err)
	}
	test.StrContains(t, stderr.String(), "Successfully joined clipboard, config written to")
	test.FileExist(t, filepath.Join(configDir, "default.conf"))
}
