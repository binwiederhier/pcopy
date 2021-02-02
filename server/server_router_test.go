package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"heckel.io/pcopy/util"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestServerRouter_InvalidConfigNoConfigs(t *testing.T) {
	_, err := NewRouter()
	if err != errInvalidNumberOfConfigs {
		t.Fatal("expected errInvalidNumberOfConfigs, got different or no error")
	}
}

func TestServerRouter_StartStopSimple(t *testing.T) {
	conf := configtest.NewTestServerConfig(t)
	conf.ServerAddr = "https://localhost:11443"
	conf.ListenHTTPS = ":11443"
	conf.ListenHTTP = ":11080"
	serverRouter := startTestServerRouter(t, conf)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "11443")
	test.WaitForPortUp(t, "11080")

	cert, _ := crypto.LoadCertFromFile(conf.CertFile)
	client := newHTTPClientWithPinnedCertAndIP(cert, "127.0.0.1:11443")

	resp, err := client.Get("https://localhost:11443/info")
	if err != nil {
		t.Fatal(err)
	}

	var info map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&info)
	test.StrEquals(t, "https://localhost:11443", info["serverAddr"].(string))

	serverRouter.Stop()
	test.WaitForPortDown(t, "11443")
	test.WaitForPortDown(t, "11080")
}

func TestServerRouter_StartStopWithVhostOnSamePorts(t *testing.T) {
	// This tests two clipboards listening on the same ports being multiplexed based on the "Host:" header
	conf1 := configtest.NewTestServerConfigWithHostname(t, "some-host-1")
	conf1.ServerAddr = "https://some-host-1:11443"
	conf1.ListenHTTPS = ":11443"
	conf1.ListenHTTP = ":11080"
	conf2 := configtest.NewTestServerConfigWithHostname(t, "some-host-2")
	conf2.ServerAddr = "https://some-host-2:12443"
	conf2.ListenHTTPS = ":11443"
	conf2.ListenHTTP = ":11080"
	serverRouter := startTestServerRouter(t, conf1, conf2)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "11443")
	test.WaitForPortUp(t, "11080")

	cert1, _ := crypto.LoadCertFromFile(conf1.CertFile)
	client1 := newHTTPClientWithPinnedCertAndIP(cert1, "127.0.0.1:11443")

	req1, _ := http.NewRequest("PUT", "https://some-host-1:11443/testfile", strings.NewReader("clipboard 1"))
	client1.Do(req1)

	cert2, _ := crypto.LoadCertFromFile(conf2.CertFile)
	client2 := newHTTPClientWithPinnedCertAndIP(cert2, "127.0.0.1:11443")
	req2, _ := http.NewRequest("PUT", "https://some-host-2:11443/testfile", strings.NewReader("clipboard 2"))
	client2.Do(req2)

	clipboardtest.Content(t, conf1, "testfile", "clipboard 1")
	clipboardtest.Content(t, conf2, "testfile", "clipboard 2")

	serverRouter.Stop()
	test.WaitForPortDown(t, "11443")
	test.WaitForPortDown(t, "11080")
}

func newHTTPClientWithPinnedCertAndIP(pinnedCert *x509.Certificate, pinnedAddr string) *http.Client {
	client, _ := util.NewHTTPClientWithPinnedCert(pinnedCert)
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.Dial(network, pinnedAddr)
	}
	return client
}

func startTestServerRouter(t *testing.T, configs ...*config.Config) *Router {
	server, err := NewRouter(configs...)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			panic(err) // 'go vet' complains about 't.Fatal(err)'
		}
	}()
	return server
}
