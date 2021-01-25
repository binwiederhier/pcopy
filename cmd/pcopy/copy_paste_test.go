package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	cmdCurlPOST := exec.Command("curl", "-sSLk", "-dabc", fmt.Sprintf("%s?f=json", config.ServerAddr))
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

func TestCurl_POSTGETRandomStreamWithJsonFormat(t *testing.T) {
	// This tests #46: curl POST with streaming and short payloads does not work (curl -dabc http://...?s=1)

	_, config := newTestConfig(t)
	server := runTestServer(t, config)
	defer server.Shutdown()

	// Streaming enabled (s=1), note that "stdbuf -oL" is required to flush buffers after every line
	cmdCurlPOST := exec.Command("stdbuf", "-oL", "curl", "-sSLk", "-dabc", fmt.Sprintf("%s?s=1&f=json", config.ServerAddr))
	stdoutPipe, _ := cmdCurlPOST.StdoutPipe()
	cmdCurlPOST.Start()

	out := waitForOutput(t, stdoutPipe, 1*time.Second, 100*time.Millisecond)
	var info map[string]interface{}
	json.Unmarshal([]byte(out), &info)

	fileId := info["file"].(string)
	curlGET := info["curl"].(string)

	file := filepath.Join(config.ClipboardDir, fileId)
	stat, _ := os.Stat(file)
	if stat.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("expected %s to be a pipe, but it's not", file)
	}

	// Now GET it
	var stdout bytes.Buffer
	cmdCurlGET := exec.Command("sh", "-c", curlGET)
	cmdCurlGET.Stdout = &stdout
	cmdCurlGET.Run()

	assertStrEquals(t, stdout.String(), "abc")
	stat, _ = os.Stat(file)
	if stat != nil {
		t.Fatalf("expected %s to not exist anymore, but it does", file)
	}
}

func waitForOutput(t *testing.T, rc io.ReadCloser, waitFirstLine time.Duration, waitRest time.Duration) string {
	reader := bufio.NewReader(rc)
	lines := make(chan string)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err == nil {
				lines <- line
			} else if err == io.EOF {
				close(lines)
				break
			}
		}
	}()
	output := make([]string, 0)
	wait := waitFirstLine
loop:
	for {
		select {
		case line := <-lines:
			output = append(output, line)
			wait = waitRest
		case <-time.After(wait):
			break loop
		}
	}
	if len(output) == 0 {
		t.Fatalf("waiting for output timed out")
	}
	return strings.Join(output, "\n")
}
