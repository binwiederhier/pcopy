package util

import (
	"io"
	"sync"
	"time"
)

const (
	defaultProgressDelay    = time.Second
	defaultProgressInterval = 150 * time.Millisecond
)

// ProgressReader counts the bytes read through it.
// Originally from https://github.com/machinebox/progress (Apache License 2.0)
type ProgressReader struct {
	reader    io.ReadCloser
	processed int64
	total     int64
	fn        ProgressFunc
	ticker    *time.Ticker
	sync.RWMutex
}

// ProgressFunc is callback that is called during copy/paste operations to indicate progress to the user.
type ProgressFunc func(processed int64, total int64, done bool)

// NewProgressReader creates a new ProgressReader using fn as the callback function for progress updates,
// and total as the optional max value that is passed through to fn. This constructor uses the default
// progress delay and interval.
func NewProgressReader(r io.ReadCloser, total int64, fn ProgressFunc) *ProgressReader {
	return NewProgressReaderWithDelay(r, total, fn, defaultProgressDelay, defaultProgressInterval)
}

// NewProgressReaderWithDelay creates a new ProgressReader using fn as the callback function for progress updates,
// and total as the optional max value that is passed through to fn. The progress function is triggered in the given
// interval, and only after certain delay.
func NewProgressReaderWithDelay(r io.ReadCloser, total int64, fn ProgressFunc, delay time.Duration, interval time.Duration) *ProgressReader {
	reader := &ProgressReader{
		reader:    r,
		processed: 0,
		total:     total,
		ticker:    nil,
		fn:        fn,
	}
	time.AfterFunc(delay, func() { reader.tick(interval) })
	return reader
}

// Read passes reads through to the underlying reader, but also updates the internal state of how many bytes
// have been processed.
func (r *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	r.Lock()
	r.processed += int64(n)
	r.Unlock()
	return
}

// Close closes the underlying reader and stops the progress update ticker. It also calls the callback function
// one last time, with the "done" flag set.
func (r *ProgressReader) Close() (err error) {
	r.Lock()
	err = r.reader.Close()
	if r.ticker != nil {
		r.ticker.Stop()
	}
	r.fn(r.processed, r.total, true)
	r.Unlock()
	return
}

func (r *ProgressReader) tick(interval time.Duration) {
	r.Lock()
	r.ticker = time.NewTicker(interval)
	r.Unlock()
	for range r.ticker.C {
		r.RLock()
		n := r.processed
		r.RUnlock()
		r.fn(n, r.total, false)
	}
}
