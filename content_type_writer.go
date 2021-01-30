package pcopy

import (
	"mime"
	"net/http"
	"strings"
)

var contentTypeExtOverrides = map[string]string{
	"text/plain": ".txt",
}

type contentTypeWriter struct {
	w        http.ResponseWriter
	filename string
	download bool
	sniffed  bool
}

func newContentTypeWriter(w http.ResponseWriter, filename string, download bool) *contentTypeWriter {
	return &contentTypeWriter{w, filename, download, false}
}

func (w *contentTypeWriter) Write(p []byte) (n int, err error) {
	if w.sniffed {
		return w.w.Write(p)
	}

	// Detect and set Content-Type header
	contentType := http.DetectContentType(p)
	if !w.download {
		// Fix content types that we don't want to inline-render in the browser. In particular,
		// we don't want to render HTML in the browser for security reasons.
		if strings.HasPrefix(contentType, "text/html") {
			contentType = strings.ReplaceAll(contentType, "text/html", "text/plain")
		} else if contentType == "application/octet-stream" {
			contentType = "" // Reset to let downstream http.ResponseWriter take care of it
		}
	}
	if contentType != "" {
		w.w.Header().Set("Content-Type", contentType)
	}

	// Set Content-Disposition header to send filename to browser
	if w.download {
		ext := ""
		filename := w.filename
		justContentType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			if extension, ok := contentTypeExtOverrides[justContentType]; ok {
				ext = extension
			} else if extensions, err := mime.ExtensionsByType(contentType); err == nil && len(extensions) > 0 {
				ext = extensions[0]
			}
		}
		if !strings.HasSuffix(filename, ext) {
			filename += ext
		}
		disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
		w.w.Header().Set("Content-Disposition", disposition)
	}

	w.sniffed = true
	return w.w.Write(p)
}
