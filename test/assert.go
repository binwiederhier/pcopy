package test

import (
	"bytes"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// StrEquals tests two strings for equality and fails t if they are not equal
func StrEquals(t *testing.T, expected string, actual string) {
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

// StrContains tests if substr is contained in s and fails t if it is not
func StrContains(t *testing.T, s string, substr string) {
	if !strings.Contains(s, substr) {
		t.Fatalf("expected %s to be contained in string, but it wasn't: %s", substr, s)
	}
}

// Int64Equals tests if two int64s for equality and fails t if they are not equal
func Int64Equals(t *testing.T, expected int64, actual int64) {
	if actual != expected {
		t.Fatalf("expected %d, got %d", expected, actual)
	}
}

// BoolEquals tests if two bools for equality and fails t if they are not equal
func BoolEquals(t *testing.T, expected bool, actual bool) {
	if actual != expected {
		t.Fatalf("expected %t, got %t", expected, actual)
	}
}

// BytesEquals tests if two byte arrays for equality and fails t if they are not equal
func BytesEquals(t *testing.T, expected []byte, actual []byte) {
	if !bytes.Equal(actual, expected) {
		t.Fatalf("expected %x, got %x", expected, actual)
	}
}

// FileNotExist asserts that a file does not exist and fails t if it does
func FileNotExist(t *testing.T, filename string) {
	if stat, _ := os.Stat(filename); stat != nil {
		t.Fatalf("expected file %s to not exist, but it does", filename)
	}
}

// FileExist asserts that a file exists and fails t if it does not
func FileExist(t *testing.T, filename string) {
	if stat, _ := os.Stat(filename); stat == nil {
		t.Fatalf("expected file %s to exist, but it does not", filename)
	}
}

// Response tests if a HTTP response status code and body match the expected values and fails t if they do not
func Response(t *testing.T, rr *httptest.ResponseRecorder, status int, body string) {
	Status(t, rr, status)
	Body(t, rr, body)
}

// Status tests if a HTTP response status code matches the expected values and fails t if it does not
func Status(t *testing.T, rr *httptest.ResponseRecorder, status int) {
	if rr.Code != status {
		t.Errorf("unexpected status code: got %v want %v", rr.Code, status)
	}
}

// Body tests if a HTTP response body matches the expected values and fails t if it does not
func Body(t *testing.T, rr *httptest.ResponseRecorder, body string) {
	if strings.TrimSpace(rr.Body.String()) != strings.TrimSpace(body) {
		t.Errorf("unexpected body: got %v want %v", strings.TrimSpace(rr.Body.String()), strings.TrimSpace(body))
	}
}
