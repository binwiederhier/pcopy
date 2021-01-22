package pcopy

import (
	"net/http"
	"strings"
)

type sniffWriter struct {
	w       http.ResponseWriter
	sniffed bool
}

func newSniffWriter(w http.ResponseWriter) *sniffWriter {
	return &sniffWriter{w, false}
}

func (w *sniffWriter) Write(p []byte) (n int, err error) {
	if w.sniffed {
		return w.w.Write(p)
	}
	contentType := http.DetectContentType(p)
	if strings.HasPrefix(contentType, "text/html") {
		contentType = strings.ReplaceAll(contentType, "text/html", "text/plain")
	} else if contentType == "application/octet-stream" {
		contentType = "" // Reset to let downstream http.ResponseWriter take care of it
	}
	if contentType != "" {
		w.w.Header().Set("Content-Type", contentType)
	}
	w.sniffed = true
	return w.w.Write(p)
}
