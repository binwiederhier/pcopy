package pcopy

import (
	"bytes"
	"testing"
)

func TestLimiter_Add(t *testing.T) {
	l := newLimiter(10)
	if err := l.Add(5); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(5); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(5); err != limitReachedError {
		t.Errorf("expected limitReachedError, got %#v", err)
	}
}

func TestLimiter_AddSet(t *testing.T) {
	l := newLimiter(10)
	l.Add(5)
	if l.Value() != 5 {
		t.Errorf("expected value to be %d, got %d", 5, l.Value())
	}
	l.Set(7)
	if l.Value() != 7 {
		t.Errorf("expected value to be %d, got %d", 7, l.Value())
	}
}

func TestLimitWriter_WriteNoLimiter(t *testing.T) {
	var buf bytes.Buffer
	lw := newLimitWriter(&buf)
	if _, err := lw.Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 11 {
		t.Errorf("expected buffer length to be %d, got %d", 11, buf.Len())
	}
}

func TestLimitWriter_WriteOneLimiter(t *testing.T) {
	var buf bytes.Buffer
	l := newLimiter(10)
	lw := newLimitWriter(&buf, l)
	if _, err := lw.Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write(make([]byte, 1)); err != limitReachedError {
		t.Errorf("expected limitReachedError, got %#v", err)
	}
	if buf.Len() != 10 {
		t.Errorf("expected buffer length to be %d, got %d", 10, buf.Len())
	}
	if l.Value() != 10 {
		t.Errorf("expected limiter value to be %d, got %d", 10, l.Value())
	}
}

func TestLimitWriter_WriteTwoLimiters(t *testing.T) {
	var buf bytes.Buffer
	l1 := newLimiter(11)
	l2 := newLimiter(9)
	lw := newLimitWriter(&buf, l1, l2)
	if _, err := lw.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write(make([]byte, 2)); err != limitReachedError {
		t.Errorf("expected limitReachedError, got %#v", err)
	}
	if buf.Len() != 8 {
		t.Errorf("expected buffer length to be %d, got %d", 8, buf.Len())
	}
	if l1.Value() != 8 {
		t.Errorf("expected limiter 1 value to be %d, got %d", 8, l1.Value())
	}
	if l2.Value() != 8 {
		t.Errorf("expected limiter 2 value to be %d, got %d", 8, l2.Value())
	}
}