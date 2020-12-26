package pcopy

import (
	"io"
	"sync"
	"time"
)

const (
	updateDelay = time.Second
	updateInterval = 150 * time.Millisecond
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
	reader := &progressReadCloser{
		reader: r,
		processed: 0,
		total: total,
		ticker: time.NewTicker(updateInterval),
		fn:     fn,
	}
	go reader.tick()
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
	r.ticker.Stop()
	r.fn(r.processed, r.total, true)
	r.Unlock()
	return
}

func (r *progressReadCloser) tick() {
	time.Sleep(updateDelay)
	for range r.ticker.C {
		r.RLock()
		n := r.processed
		r.RUnlock()
		r.fn(n, r.total, false)
	}
}
