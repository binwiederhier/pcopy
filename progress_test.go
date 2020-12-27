package pcopy

import (
	"io/ioutil"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProgressReadCloser_NoDelay(t *testing.T) {
	ticks := int32(0)
	processed := int64(0)
	total := int64(0)
	fn := func(p int64, t int64, d bool) {
		atomic.StoreInt64(&processed, p)
		atomic.StoreInt64(&total, t)
		atomic.AddInt32(&ticks, 1)
	}
	r := ioutil.NopCloser(strings.NewReader("this is a 34 byte long test string"))
	p := newProgressReaderWithDelay(r, 34, fn, 0, 50 * time.Millisecond)

	// First tick (no progress)
	time.Sleep(51 * time.Millisecond)
	if atomic.LoadInt32(&ticks) != 1 {
		t.Fatalf("expected 1 tick, got %d", atomic.LoadInt32(&ticks))
	}
	if atomic.LoadInt64(&processed) != 0 {
		t.Fatalf("expected processed to be 0, got %d", atomic.LoadInt64(&processed))
	}
	if atomic.LoadInt64(&total) != 34 {
		t.Fatalf("expected total to be 100, got %d", atomic.LoadInt64(&total))
	}

	// Second tick
	if _, err := p.Read(make([]byte, 11)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(51 * time.Millisecond)
	if atomic.LoadInt32(&ticks) != 2 {
		t.Fatalf("expected 2 ticks, got %d", atomic.LoadInt32(&ticks))
	}
	if atomic.LoadInt64(&processed) != 11 {
		t.Fatalf("expected processed to be 11, got %d", atomic.LoadInt64(&processed))
	}
	if atomic.LoadInt64(&total) != 34 {
		t.Fatalf("expected total to be 100, got %d", atomic.LoadInt64(&total))
	}

	// Third tick
	if _, err := p.Read(make([]byte, 999)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(51 * time.Millisecond)
	if atomic.LoadInt32(&ticks) != 3 {
		t.Fatalf("expected 3 ticks, got %d", atomic.LoadInt32(&ticks))
	}
	if atomic.LoadInt64(&processed) != 34 {
		t.Fatalf("expected processed to be 100, got %d", atomic.LoadInt64(&processed))
	}
	if atomic.LoadInt64(&total) != 34 {
		t.Fatalf("expected total to be 100, got %d", atomic.LoadInt64(&total))
	}
}

// TODO TestProgressReadCloser_WithDelay
