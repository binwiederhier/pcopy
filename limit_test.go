package pcopy

import "testing"

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
