package util

import (
	"heckel.io/pcopy/test"
	"io"
	"strings"
	"testing"
)

func TestPeak_LimitReached(t *testing.T) {
	underlying := io.NopCloser(strings.NewReader("1234567890"))
	peaked, err := Peak(underlying, 5)
	if err != nil {
		t.Fatal(err)
	}
	test.BytesEquals(t, []byte("12345"), peaked.Peaked)
	test.BoolEquals(t, true, peaked.LimitReached)

	all, err := io.ReadAll(peaked)
	if err != nil {
		t.Fatal(err)
	}
	test.BytesEquals(t, []byte("1234567890"), all)
	test.BytesEquals(t, []byte("12345"), peaked.Peaked)
	test.BoolEquals(t, true, peaked.LimitReached)
}

func TestPeak_LimitNotReached(t *testing.T) {
	underlying := io.NopCloser(strings.NewReader("1234567890"))
	peaked, err := Peak(underlying, 15)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(peaked)
	if err != nil {
		t.Fatal(err)
	}
	test.BytesEquals(t, []byte("1234567890"), all)
	test.BytesEquals(t, []byte("1234567890"), peaked.Peaked)
	test.BoolEquals(t, false, peaked.LimitReached)
}
