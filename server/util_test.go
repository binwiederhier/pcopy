package server

import (
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"strings"
	"testing"
)

func TestGenerateURLUnprotected(t *testing.T) {
	conf := config.New()
	conf.ServerAddr = "some-host.com"

	url, err := generateURL(conf, "/some-path", "secreT")
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, "https://some-host.com:2586/some-path?a=secreT", url)
}

func TestGenerateURLProtected(t *testing.T) {
	conf := config.New()
	conf.ServerAddr = "some-host.com"
	conf.Key = &crypto.Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}

	url, err := generateURL(conf, "/some-path", "my-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "https://some-host.com:2586/some-path?a=my-secret") {
		t.Fatalf("expected URL mismatched, got %s", url)
	}
}

func TestConfig_GenerateURL443(t *testing.T) {
	conf := config.New()
	conf.ServerAddr = "some-host.com:443"

	url, err := generateURL(conf, "/some-path", "some-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "https://some-host.com/some-path?a=some-secret") {
		t.Fatalf("expected URL mismatched, got %s", url)
	}
}
