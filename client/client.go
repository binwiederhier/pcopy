// Package client provides the pcopy client that can be used to its server
package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/server"
	"heckel.io/pcopy/util"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	useDefaultAuthTTL = 0
)

// Client represents a pcopy client. It can be used to communicate with the server to
// verify the user password, and ultimately to copy/paste files.
type Client struct {
	config     *config.Config
	httpClient *http.Client // Allow injecting HTTP client for testing
}

// NewClient creates a new pcopy client. It fails if the ServerAddr is not filled.
func NewClient(conf *config.Config) (*Client, error) {
	if conf.ServerAddr == "" {
		return nil, errMissingServerAddr
	}
	return &Client{
		config: conf,
	}, nil
}

// Copy streams the data from reader to the server via a HTTP PUT request. The id parameter
// is the file identifier that can be used to paste the data later using Paste.
func (c *Client) Copy(reader io.ReadCloser, id string, ttl time.Duration, mode string, stream bool) (*server.File, error) {
	client, err := c.newHTTPClient(nil)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s", config.ExpandServerAddr(c.config.ServerAddr), id)
	req, err := http.NewRequest(http.MethodPut, url, c.withProgressReader(reader, -1))
	if err != nil {
		return nil, err
	}
	if err := c.addAuthHeader(req, nil); err != nil {
		return nil, err
	}
	req.Header.Set(server.HeaderFormat, server.HeaderFormatNone)
	if ttl > 0 {
		req.Header.Set(server.HeaderTTL, ttl.String())
	}
	if mode != "" {
		req.Header.Set(server.HeaderFileMode, mode)
	}
	if stream {
		req.Header.Set(server.HeaderStream, server.HeaderStreamDelayHeaders)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	} else if resp.StatusCode == http.StatusPartialContent {
		return nil, server.ErrHTTPPartialContent
	} else if resp.StatusCode == http.StatusRequestEntityTooLarge {
		return nil, server.ErrHTTPPayloadTooLarge
	} else if resp.StatusCode != http.StatusOK {
		return nil, &server.ErrHTTP{Code: resp.StatusCode, Status: resp.Status}
	}

	return c.parseFileInfoResponse(resp)
}

// CopyFiles creates a ZIP archive of the given files and streams it to the server using the Copy
// method. No temporary ZIP archive is created on disk. It's all streamed.
func (c *Client) CopyFiles(files []string, id string, ttl time.Duration, mode string, stream bool) (*server.File, error) {
	zipReader, err := util.NewZIPReader(files)
	if err != nil {
		return nil, err
	}
	return c.Copy(zipReader, id, ttl, mode, stream)
}

// Reserve requests a file name from the server and reserves it for a very short period
// of time. This is a workaround to be able to stream to a random file ID.
func (c *Client) Reserve(id string) (*server.File, error) {
	client, err := c.newHTTPClient(nil)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s", config.ExpandServerAddr(c.config.ServerAddr), id)
	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		return nil, err
	}
	if err := c.addAuthHeader(req, nil); err != nil {
		return nil, err
	}
	req.Header.Set(server.HeaderReserve, server.HeaderReserveEnabled)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		return nil, &server.ErrHTTP{Code: resp.StatusCode, Status: resp.Status}
	}

	return c.parseFileInfoResponse(resp)
}

// Paste reads the file with the given id from the server and writes it to writer.
func (c *Client) Paste(writer io.Writer, id string) error {
	client, err := c.newHTTPClient(nil)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s", config.ExpandServerAddr(c.config.ServerAddr), id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if err := c.addAuthHeader(req, nil); err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	} else if resp.Body == nil {
		return errResponseBodyEmpty
	} else if resp.StatusCode != http.StatusOK {
		return &server.ErrHTTP{Code: resp.StatusCode, Status: resp.Status}
	}

	var total int
	total, err = strconv.Atoi(resp.Header.Get("Length"))
	if err != nil {
		total = 0
	}

	reader := c.withProgressReader(resp.Body, int64(total))
	defer reader.Close()

	if _, err := io.Copy(writer, reader); err != nil {
		return err
	}

	return nil
}

// PasteFiles reads the file with the given id from the server (assuming that it is a ZIP archive)
// and unpacks it to dir. This method creates a temporary file of the archive first before unpacking.
func (c *Client) PasteFiles(dir string, id string) error {
	// Heavily inspired by: https://golangcode.com/unzip-files-in-go/

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmpFile, err := ioutil.TempFile(dir, ".pcopy-paste.*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	f, err := os.OpenFile(tmpFile.Name(), os.O_RDWR|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := c.Paste(f, id); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := util.ExtractZIP(tmpFile.Name(), dir); err != nil {
		return err
	}
	return nil
}

// FileInfo retrieves file metadata for the given file
func (c *Client) FileInfo(id string) (*server.File, error) {
	client, err := c.newHTTPClient(nil)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s", config.ExpandServerAddr(c.config.ServerAddr), id)
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	if err := c.addAuthHeader(req, nil); err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		return nil, &server.ErrHTTP{Code: resp.StatusCode, Status: resp.Status}
	}

	return c.parseFileInfoResponse(resp)
}

// ServerInfo queries the server for information (password salt, advertised address) required during the
// join operation. This method will first attempt to securely connect over HTTPS, and (if that fails)
// fall back to skipping certificate verification. In the latter case, it will download and return
// the server certificate so the client can pin them.
func (c *Client) ServerInfo() (*server.Info, error) {
	var cert *x509.Certificate
	var err error

	// First attempt to retrieve info with secure HTTP client
	info, err := c.retrieveInfo(&http.Client{})
	if err != nil {
		// Then attempt to retrieve ignoring bad certs (this is okay, we pin the cert if it's bad)
		insecureTransport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		insecureClient := &http.Client{Transport: insecureTransport}
		info, err = c.retrieveInfo(insecureClient)
		if err != nil {
			return nil, err
		}

		// Retrieve bad cert(s) for cert pinning
		cert, err = c.retrieveCert()
		if err != nil {
			return nil, err
		}
	}

	return &server.Info{
		ServerAddr: info.ServerAddr,
		Salt:       info.Salt,
		Cert:       cert,
	}, nil
}

// Verify verifies that the given key (derived from the user password) is in fact correct
// by calling the server's verify endpoint. If the call fails, the key is assumed to be incorrect.
func (c *Client) Verify(cert *x509.Certificate, key *crypto.Key) error {
	client, err := c.newHTTPClient(cert)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/verify", config.ExpandServerAddr(c.config.ServerAddr))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if err := c.addAuthHeader(req, key); err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	} else if resp.StatusCode != http.StatusOK {
		return &server.ErrHTTP{Code: resp.StatusCode, Status: resp.Status}
	}

	return nil
}

func (c *Client) addAuthHeader(req *http.Request, key *crypto.Key) error {
	if key == nil {
		key = c.config.Key
	}
	if key == nil {
		return nil // No auth configured
	}

	auth, err := crypto.GenerateAuthHMAC(key.Bytes, req.Method, req.URL.Path, useDefaultAuthTTL) // RequestURI is empty!
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", auth)
	return nil
}

func (c *Client) withProgressReader(reader io.ReadCloser, total int64) io.ReadCloser {
	if c.config.ProgressFunc != nil {
		return util.NewProgressReader(reader, total, c.config.ProgressFunc)
	}
	return reader
}

func (c *Client) parseFileInfoResponse(resp *http.Response) (*server.File, error) {
	expires, err := strconv.ParseInt(resp.Header.Get(server.HeaderExpires), 10, 64)
	if err != nil {
		expires = 0
	}
	ttl, err := strconv.ParseInt(resp.Header.Get(server.HeaderTTL), 10, 64)
	if err != nil {
		ttl = 0
	}
	return &server.File{
		File:    resp.Header.Get(server.HeaderFile),
		URL:     resp.Header.Get(server.HeaderURL),
		Expires: time.Unix(expires, 0),
		TTL:     time.Duration(ttl) * time.Second,
		Curl:    resp.Header.Get(server.HeaderCurl),
	}, nil
}

func (c *Client) retrieveInfo(client *http.Client) (*server.Info, error) {
	resp, err := client.Get(fmt.Sprintf("%s/info", config.ExpandServerAddr(c.config.ServerAddr)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info server.Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// retrieveCert opens a raw TLS connection and retrieves the leaf certificate
func (c *Client) retrieveCert() (*x509.Certificate, error) {
	u, err := url.Parse(config.ExpandServerAddr(c.config.ServerAddr))
	if err != nil {
		return nil, err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return nil, errNoPeerCert
	}
	return conn.ConnectionState().PeerCertificates[0], nil
}

func (c *Client) newHTTPClient(cert *x509.Certificate) (*http.Client, error) {
	if c.httpClient != nil { // For testing only!
		return c.httpClient, nil
	} else if cert != nil {
		return util.NewHTTPClientWithPinnedCert(cert)
	} else if c.config.CertFile != "" {
		cert, err := crypto.LoadCertFromFile(c.config.CertFile)
		if err != nil {
			return nil, err
		}
		return util.NewHTTPClientWithPinnedCert(cert)
	} else {
		return &http.Client{}, nil
	}
}

var errMissingServerAddr = errors.New("server address missing")
var errResponseBodyEmpty = errors.New("response body was empty")
var errNoPeerCert = errors.New("no peer cert found")
