package main

import (
	"fmt"
	"os/exec"
	"testing"
)

func TestCLI_Copy(t *testing.T) {
	filename, config := newTestConfig(t)
	server := runTestServer(t, config)

	fds := tempFDsWithSTDIN(t, "test stdin")
	if err := runApp(fds, "pcp", "-c", filename); err != nil {
		t.Fatal(err)
	}
	server.Shutdown()

	assertFileContent(t, config, "default", "test stdin")
	assertFdContains(t, fds.err, "Direct link (valid for 7d")
	assertFdContains(t, fds.err, "curl -sSLk --pinnedpubkey")
	assertFdContains(t, fds.err, "https://localhost:12345/default")
}

func TestCLI_CopyPaste(t *testing.T) {
	filename, config := newTestConfig(t)
	server := runTestServer(t, config)

	copyFDs := tempFDsWithSTDIN(t, "this is a test string")
	if err := runApp(copyFDs, "pcp", "-c", filename, "somefile"); err != nil {
		t.Fatal(err)
	}
	pasteFDs := tempFDs(t)
	if err := runApp(pasteFDs, "ppaste", "-c", filename, "somefile"); err != nil {
		t.Fatal(err)
	}
	server.Shutdown()

	assertFdContains(t, copyFDs.err, "https://localhost:12345/somefile")
	assertFdContains(t, pasteFDs.out, "this is a test string")
}

func TestCurl_CopyPOSTSuccess(t *testing.T) {
	_, config := newTestConfig(t)
	server := runTestServer(t, config)

	fds, cmd := commandWithTempFDs(t, "curl", "-sSLk", "-dabc", fmt.Sprintf("%s/howdy?f=json", config.ServerAddr))
	cmd.Run()
	server.Shutdown()

	assertFileContent(t, config, "howdy", "abc")
	assertFdContains(t, fds.out, `"url":"https://localhost:12345/howdy"`) // json
}

func commandWithTempFDs(t *testing.T, name string, args ...string) (*stdFDs, *exec.Cmd) {
	fds := tempFDs(t)
	cmd := exec.Command(name, args...)
	cmd.Stdin = fds.in
	cmd.Stdout = fds.out
	cmd.Stderr = fds.err
	return fds, cmd
}
