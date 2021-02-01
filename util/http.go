package util

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
)

var errNoTrustedCertMatch = errors.New("no trusted cert matches")

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
