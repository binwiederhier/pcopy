package pcopy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServerRouter_InvalidConfigNoConfigs(t *testing.T) {
	_, err := NewServerRouter()
	if err != errInvalidNumberOfConfigs {
		t.Fatal("expected errInvalidNumberOfConfigs, got different or no error")
	}
}

func TestServerRouter_StartStopSimple(t *testing.T) {
	config := newTestServerConfig(t)
	config.ServerAddr = "https://localhost:11443"
	config.ListenHTTPS = ":11443"
	config.ListenHTTP = ":11080"
	serverRouter := startTestServerRouter(t, config)
	defer serverRouter.Stop()

	waitForPortUp(t, "11443")
	waitForPortUp(t, "11080")

	cert, _ := LoadCertFromFile(config.CertFile)
	client := newHTTPClientWithPinnedCertAndIP(cert, "127.0.0.1:11443")

	resp, err := client.Get("https://localhost:11443/info")
	if err != nil {
		t.Fatal(err)
	}

	var info map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&info)
	assertStrEquals(t, "https://localhost:11443", info["serverAddr"].(string))

	serverRouter.Stop()
	waitForPortDown(t, "11443")
	waitForPortDown(t, "11080")
}

func TestServerRouter_StartStopWithVhostOnSamePorts(t *testing.T) {
	// This tests two clipboards listening on the same ports being multiplexed based on the "Host:" header
	config1 := newTestServerConfigWithHostname(t, "some-host-1")
	config1.ServerAddr = "https://some-host-1:11443"
	config1.ListenHTTPS = ":11443"
	config1.ListenHTTP = ":11080"
	config2 := newTestServerConfigWithHostname(t, "some-host-2")
	config2.ServerAddr = "https://some-host-2:12443"
	config2.ListenHTTPS = ":11443"
	config2.ListenHTTP = ":11080"
	serverRouter := startTestServerRouter(t, config1, config2)
	defer serverRouter.Stop()

	waitForPortUp(t, "11443")
	waitForPortUp(t, "11080")

	cert1, _ := LoadCertFromFile(config1.CertFile)
	client1 := newHTTPClientWithPinnedCertAndIP(cert1, "127.0.0.1:11443")

	req1, _ := http.NewRequest("PUT", "https://some-host-1:11443/testfile", strings.NewReader("clipboard 1"))
	client1.Do(req1)

	cert2, _ := LoadCertFromFile(config2.CertFile)
	client2 := newHTTPClientWithPinnedCertAndIP(cert2, "127.0.0.1:11443")
	req2, _ := http.NewRequest("PUT", "https://some-host-2:11443/testfile", strings.NewReader("clipboard 2"))
	client2.Do(req2)

	assertFileContent(t, config1, "testfile", "clipboard 1")
	assertFileContent(t, config2, "testfile", "clipboard 2")

	serverRouter.Stop()
	waitForPortDown(t, "11443")
	waitForPortDown(t, "11080")
}

func newHTTPClientWithPinnedCertAndIP(pinnedCert *x509.Certificate, pinnedAddr string) *http.Client {
	client, _ := newHTTPClientWithPinnedCert(pinnedCert)
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		return dialer.Dial(network, pinnedAddr)
	}
	return client
}

func startTestServerRouter(t *testing.T, configs ...*Config) *ServerRouter {
	server, err := NewServerRouter(configs...)
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

func waitForPortUp(t *testing.T, port string) {
	success := false
	for i := 0; i < 100; i++ {
		conn, _ := net.DialTimeout("tcp", net.JoinHostPort("", port), 20*time.Millisecond)
		if conn != nil {
			success = true
			conn.Close()
			break
		}
	}
	if !success {
		t.Fatalf("Failed waiting for port %s to be UP", port)
	}
}

func waitForPortDown(t *testing.T, port string) {
	success := false
	for i := 0; i < 20; i++ {
		conn, _ := net.DialTimeout("tcp", net.JoinHostPort("", port), 20*time.Millisecond)
		if conn == nil {
			success = true
			break
		}
		conn.Close()
	}
	if !success {
		t.Fatalf("Failed waiting for port %s to be DOWN", port)
	}
}
