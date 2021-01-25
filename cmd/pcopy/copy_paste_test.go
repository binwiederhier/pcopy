package main

import (
	"bytes"
	"encoding/json"
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
	defer server.Shutdown()

	var stdout bytes.Buffer
	cmd := exec.Command("curl", "-sSLk", "-dabc", fmt.Sprintf("%s/howdy?f=json", config.ServerAddr))
	cmd.Stdout = &stdout
	cmd.Run()

	assertFileContent(t, config, "howdy", "abc")
	assertStrContains(t, stdout.String(), `"url":"https://localhost:12345/howdy"`) // json
}

func TestCurl_POSTGETRandomWithJsonFormat(t *testing.T) {
	_, config := newTestConfig(t)
	server := runTestServer(t, config)
	defer server.Shutdown()

	var stdout bytes.Buffer
	cmdCurlPOST := exec.Command("curl", "-sSLk", "-dabc", fmt.Sprintf("%s?f=json", "https://plep.nopaste.net"))
	cmdCurlPOST.Stdout = &stdout
	cmdCurlPOST.Run()

	var info map[string]interface{}
	json.Unmarshal([]byte(stdout.String()), &info)

	stdout.Reset()
	cmdCurlGET := exec.Command("sh", "-c", info["curl"].(string))
	cmdCurlGET.Stdout = &stdout
	cmdCurlGET.Run()

	assertStrEquals(t, stdout.String(), "abc")
}
