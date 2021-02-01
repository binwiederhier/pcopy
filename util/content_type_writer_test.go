package util

import (
	"crypto/rand"
	"heckel.io/pcopy/test"
	"net/http/httptest"
	"testing"
)

func TestSniffWriter_WriteHTML(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "", false)
	sw.Write([]byte("<script>alert('hi')</script>"))
	test.StrEquals(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_WriteTwoWriteCalls(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "", false)
	sw.Write([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x11, 0x22, 0x33})
	sw.Write([]byte("<script>alert('hi')</script>"))
	test.StrEquals(t, "application/pdf", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_NoSniffWriterWriteHTML(t *testing.T) {
	// This test just makes sure that without the sniff-w, we would get text/html

	rr := httptest.NewRecorder()
	rr.Write([]byte("<script>alert('hi')</script>"))
	test.StrEquals(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_WriteHTMLSplitIntoTwoWrites(t *testing.T) {
	// This test shows how splitting the HTML into two Write() calls will still yield text/plain

	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "", false)
	sw.Write([]byte("<scr"))
	sw.Write([]byte("ipt>alert('hi')</script>"))
	test.StrEquals(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_WriteUnknownMimeType(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "", false)
	randomBytes := make([]byte, 199)
	rand.Read(randomBytes)
	sw.Write(randomBytes)
	test.StrEquals(t, "application/octet-stream", rr.Header().Get("Content-Type"))
}

func TestSniffWriter_DownloadWithFilename(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "some file", true)
	sw.Write([]byte("this is a text file"))
	test.StrEquals(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
	test.StrEquals(t, `attachment; filename="some file.txt"`, rr.Header().Get("Content-Disposition"))
}

func TestSniffWriter_DownloadWithSpecialCharFilename(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "öäü().pdf", true)
	sw.Write([]byte{0x25, 0x50, 0x44, 0x46, 0x2d, 0x11, 0x22, 0x33})
	test.StrEquals(t, "application/pdf", rr.Header().Get("Content-Type"))
	test.StrEquals(t, `attachment; filename*=utf-8''%C3%B6%C3%A4%C3%BC%28%29.pdf`, rr.Header().Get("Content-Disposition"))
}

func TestSniffWriter_DownloadWithUnknownMimeType(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := NewContentTypeWriter(rr, "abcdef", true)
	randomBytes := make([]byte, 199)
	rand.Read(randomBytes)
	sw.Write(randomBytes)
	test.StrEquals(t, "application/octet-stream", rr.Header().Get("Content-Type"))
	test.StrEquals(t, `attachment; filename=abcdef.bin`, rr.Header().Get("Content-Disposition"))
}
