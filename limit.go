package pcopy

import (
	"errors"
	"io"
	"sync"
)

type limitWriter struct {
	writer io.Writer
	written int64
	limit int64
	sync.RWMutex
}

var limitError = errors.New("cannot write, limit reached")

func newLimitWriter(w io.Writer, limit int64) io.Writer {
	return &limitWriter{
		writer: w,
		limit: limit,
	}
}

func (w *limitWriter) Write(p []byte) (n int, err error) {
	w.Lock()
	defer w.Unlock()
	if w.limit > 0 && w.written + int64(len(p)) > w.limit {
		return 0, limitError
	}
	n, err = w.writer.Write(p)
	w.written += int64(n)
	return
}