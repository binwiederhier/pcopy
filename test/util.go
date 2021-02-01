package test

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// FromBase64 converts a base64 string to a byte array and fails t if that fails
func FromBase64(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// WaitForPortUp waits up to 5s for a port to come up and fails t if that fails
func WaitForPortUp(t *testing.T, port string) {
	success := false
	for i := 0; i < 100; i++ {
		conn, _ := net.DialTimeout("tcp", net.JoinHostPort("localhost", port), 50*time.Millisecond)
		if conn != nil {
			success = true
			conn.Close()
			break
		}
	}
	if !success {
		t.Fatalf("Failed waiting for port %s to be UP", port)
	}
}

// WaitForPortDown waits up to 5s for a port to come down and fails t if that fails
func WaitForPortDown(t *testing.T, port string) {
	success := false
	for i := 0; i < 100; i++ {
		conn, _ := net.DialTimeout("tcp", net.JoinHostPort("", port), 50*time.Millisecond)
		if conn == nil {
			success = true
			break
		}
		conn.Close()
	}
	if !success {
		t.Fatalf("Failed waiting for port %s to be DOWN", port)
	}
}

// WaitForOutput reads rc line by line and returns the entire contents or fails t if that fails.
// The function waits a period of time for the first line and then for the rest of the stream.
func WaitForOutput(t *testing.T, rc io.ReadCloser, waitFirstLine time.Duration, waitRest time.Duration) string {
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
