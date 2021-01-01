package pcopy

import (
	"errors"
	"io"
	"sync"
)

type limiter struct {
	value int64
	limit int64
	sync.Mutex
}

func newLimiter(limit int64) *limiter {
	return &limiter{
		limit: limit,
	}
}

func (l *limiter) Set(n int64) {
	l.Lock()
	l.value = n
	l.Unlock()
}

func (l *limiter) Add(n int64) error {
	l.Lock()
	defer l.Unlock()
	if l.limit == 0 {
		return nil
	} else if l.value+n <= l.limit {
		l.value += n
		return nil
	} else {
		return errLimitReached
	}
}

func (l *limiter) Sub(n int64) {
	l.Add(-n)
}

func (l *limiter) Value() int64 {
	l.Lock()
	defer l.Unlock()
	return l.value
}

func (l *limiter) Limit() int64 {
	return l.limit
}

type limitWriter struct {
	writer   io.Writer
	written  int64
	limiters []*limiter
	sync.RWMutex
}

func newLimitWriter(w io.Writer, limiters ...*limiter) io.Writer {
	return &limitWriter{
		writer:   w,
		limiters: limiters,
	}
}

func (w *limitWriter) Write(p []byte) (n int, err error) {
	w.Lock()
	defer w.Unlock()
	for i := 0; i < len(w.limiters); i++ {
		if err := w.limiters[i].Add(int64(len(p))); err != nil {
			for j := i - 1; j >= 0; j-- {
				w.limiters[j].Sub(int64(len(p)))
			}
			return 0, errLimitReached
		}
	}
	n, err = w.writer.Write(p)
	w.written += int64(n)
	return
}

var errLimitReached = errors.New("limit reached")
