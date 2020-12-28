package pcopy

import (
	"testing"
	"time"
)

func TestParseDurationWithDaysSuccess(t *testing.T) {
	d, err := parseDuration("10d")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10 * 24 * time.Hour {
		t.Fatalf("expected %d, got %d", 10 * 24 * time.Hour, d)
	}
}

func TestParseDurationWithoutDaysSuccess(t *testing.T) {
	d, err := parseDuration("10h5m")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10 * time.Hour + 5 * time.Minute {
		t.Fatalf("expected %d, got %d", 10 * time.Hour + 5 * time.Minute, d)
	}
}

func TestParseDurationWithDaysAndHoursFailure(t *testing.T) {
	_, err := parseDuration("10d1h") // not supported
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}
