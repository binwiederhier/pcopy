package pcopy

import (
	"crypto/rand"
	"net/http/httptest"
	"testing"
)

func TestSniffWriter_WriteHTML(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := newContentTypeWriter(rr, "", false)
	sw.Write([]byte("<script>alert('hi')</script>"))
	assertStrEquals(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_WriteTwoWriteCalls(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := newContentTypeWriter(rr, "", false)
	sw.Write([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x11, 0x22, 0x33})
	sw.Write([]byte("<script>alert('hi')</script>"))
	assertStrEquals(t, "application/pdf", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_NoSniffWriterWriteHTML(t *testing.T) {
	// This test just makes sure that without the sniff-writer, we would get text/html

	rr := httptest.NewRecorder()
	rr.Write([]byte("<script>alert('hi')</script>"))
	assertStrEquals(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_WriteHTMLSplitIntoTwoWrites(t *testing.T) {
	// This test shows how splitting the HTML into two Write() calls will still yield text/plain

	rr := httptest.NewRecorder()
	sw := newContentTypeWriter(rr, "", false)
	sw.Write([]byte("<scr"))
	sw.Write([]byte("ipt>alert('hi')</script>"))
	assertStrEquals(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_WriteBinary(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := newContentTypeWriter(rr, "", false)
	randomBytes := make([]byte, 199)
	rand.Read(randomBytes)
	sw.Write(randomBytes)
	assertStrEquals(t, "application/octet-stream", rr.Header().Get("Content-Type"))
}
