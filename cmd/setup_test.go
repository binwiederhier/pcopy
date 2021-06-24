package cmd

import (
	"encoding/base64"
	"fmt"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/test"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestCLI_Setup(t *testing.T) {
	configDir := t.TempDir()
	configFile := filepath.Join(configDir, "server.conf")
	clipboardDir := t.TempDir()
	usr, _ := user.Current()

	app, stdin, _, stderr := newTestApp()
	stdin.WriteString(configFile + "\n")
	stdin.WriteString(clipboardDir + "\n")
	stdin.WriteString(":12345\n")          // listen address
	stdin.WriteString("localhost:12345\n") // server address
	stdin.WriteString("i'm a password\n")
	if usr.Uid == "0" {
		stdin.WriteString("\n") // install systemd service
	}
	stdin.WriteString("\n") // confirm

	if err := Run(app, "pcopy", "setup"); err != nil {
		fmt.Println(stderr.String())
		t.Fatal(err)
	}

	test.StrContains(t, stderr.String(), "Success. You may now start the server by running")
	test.FileExist(t, configFile)
	test.FileExist(t, config.DefaultCertFile(configFile, true))
	test.FileExist(t, config.DefaultKeyFile(configFile, true))

	// Now start and join the clipboard
	serverConf, _ := config.LoadFromFile(configFile)
	serverRouter := startTestServerRouter(t, serverConf)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "12345")

	clientConfigDir := t.TempDir()
	os.Setenv(config.EnvConfigDir, clientConfigDir)

	joinApp, joinStdin, _, joinStderr := newTestApp()
	joinStdin.WriteString("i'm a password")

	if err := Run(joinApp, "pcopy", "join", "localhost:12345"); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(filepath.Join(clientConfigDir, "default.conf"))
	saltBase64 := base64.StdEncoding.EncodeToString(serverConf.Key.Salt)

	test.StrContains(t, joinStderr.String(), "Successfully joined clipboard, config written to")
	test.StrContains(t, string(content), saltBase64)
	test.FileExist(t, filepath.Join(clientConfigDir, "default.conf"))

}
