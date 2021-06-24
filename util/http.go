package util

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"
)

const (
	// EnvHTTPClientTimeout allows overriding the HTTP client timeout (use for tests only)
	EnvHTTPClientTimeout = "PCOPY_HTTP_CLIENT_TIMEOUT"

	defaultHTTPClientTimeout = 5 * time.Second
)

var errNoTrustedCertMatch = errors.New("no trusted cert matches")

// NewHTTPClient returns a HTTP client
func NewHTTPClient() *http.Client {
	return &http.Client{}
}

// NewHTTPClientWithInsecureTransport returns a HTTP client that will accept any TLS certificate. Use this
// only for testing or unless you know what you're doing.
func NewHTTPClientWithInsecureTransport() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// NewHTTPClientWithPinnedCert is a helper function to create a HTTP client with a pinned TLS certificate.
// Communication with a HTTPS server with a different certificate will fail.
func NewHTTPClientWithPinnedCert(pinned *x509.Certificate) (*http.Client, error) {
	verifyCertFn := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, r := range rawCerts {
			if bytes.Equal(pinned.Raw, r) {
				return nil
			}
		}
		return errNoTrustedCertMatch
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify:    true, // Certs are checked manually
				VerifyPeerCertificate: verifyCertFn,
			},
		},
	}, nil
}

// WithTimeout adds a timeout to the given client
func WithTimeout(client *http.Client) *http.Client {
	client.Timeout = getHTTPClientTimeout()
	return client
}

func getHTTPClientTimeout() time.Duration {
	overrideTimeoutStr := os.Getenv(EnvHTTPClientTimeout)
	if overrideTimeoutStr != "" {
		if overrideTimeout, err := ParseDuration(overrideTimeoutStr); err == nil {
			return overrideTimeout
		}
	}
	return defaultHTTPClientTimeout
}
