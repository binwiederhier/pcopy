package server

import (
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"strings"
	"testing"
	"time"
)

func TestGenerateURLUnprotected(t *testing.T) {
	conf := config.New()
	conf.ServerAddr = "some-host.com"

	url, err := generateURL(conf, "/some-path", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "https://some-host.com:2586/some-path", url)
}

func TestGenerateURLProtected(t *testing.T) {
	conf := config.New()
	conf.ServerAddr = "some-host.com"
	conf.Key = &crypto.Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}

	url, err := generateURL(conf, "/some-path", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "https://some-host.com:2586/some-path?a=SE1BQyA") {
		t.Fatalf("expected URL mismatched, got %s", url)
	}
	// TODO This should actually validate the HMAC, but the authorize() method is in server.go
}

func TestConfig_GenerateURL443(t *testing.T) {
	conf := config.New()
	conf.ServerAddr = "some-host.com:443"

	url, err := generateURL(conf, "/some-path", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "https://some-host.com/some-path") {
		t.Fatalf("expected URL mismatched, got %s", url)
	}
}
