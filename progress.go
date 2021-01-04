package pcopy

import (
	"io"
	"sync"
	"time"
)

const (
	defaultProgressDelay    = time.Second
	defaultProgressInterval = 150 * time.Millisecond
)

// progressReadCloser counts the bytes read through it.
// Originally from https://github.com/machinebox/progress (Apache License 2.0)
type progressReadCloser struct {
	reader    io.ReadCloser
	processed int64
	total     int64
	fn        ProgressFunc
	ticker    *time.Ticker
	sync.RWMutex
}

func newProgressReader(r io.ReadCloser, total int64, fn ProgressFunc) *progressReadCloser {
	return newProgressReaderWithDelay(r, total, fn, defaultProgressDelay, defaultProgressInterval)
}

func newProgressReaderWithDelay(r io.ReadCloser, total int64, fn ProgressFunc, delay time.Duration, interval time.Duration) *progressReadCloser {
	reader := &progressReadCloser{
		reader:    r,
		processed: 0,
		total:     total,
		ticker:    nil,
		fn:        fn,
	}
	time.AfterFunc(delay, func() { reader.tick(interval) })
	return reader
}

func (r *progressReadCloser) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	r.Lock()
	r.processed += int64(n)
	r.Unlock()
	return
}

func (r *progressReadCloser) Close() (err error) {
	r.Lock()
	err = r.reader.Close()
	if r.ticker != nil {
		r.ticker.Stop()
	}
	r.fn(r.processed, r.total, true)
	r.Unlock()
	return
}

func (r *progressReadCloser) tick(interval time.Duration) {
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
