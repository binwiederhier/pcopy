package pcopy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
)

// Client represents a pcopy client. It can be used to communicate with the server to
// verify the user password, and ultimately to copy/paste files.
type Client struct {
	config     *Config
	httpClient *http.Client // Allow injecting HTTP client for testing
}

// ServerInfo contains information about the server needed o join a server.
type ServerInfo struct {
	ServerAddr string
	Salt       []byte
	Cert       *x509.Certificate
}

// NewClient creates a new pcopy client. It fails if the ServerAddr is not filled.
func NewClient(config *Config) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, errMissingServerAddr
	}
	return &Client{
		config: config,
	}, nil
}

// Copy streams the data from reader to the server via a HTTP PUT request. The id parameter
// is the file identifier that can be used to paste the data later using Paste.
func (c *Client) Copy(reader io.ReadCloser, id string) error {
	client, err := c.newHTTPClient(nil)
	if err != nil {
		return err
	}

	path := fmt.Sprintf(clipboardPathFormat, id)
	url := fmt.Sprintf("https://%s%s", c.config.ServerAddr, path)
	req, err := http.NewRequest(http.MethodPut, url, c.withProgressReader(reader, -1))
	if err != nil {
		return err
	}
	if err := c.addAuthHeader(req, nil); err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	} else if resp.StatusCode != http.StatusOK {
		return &errHTTPNotOK{resp.StatusCode, resp.Status}
	}

	return nil
}

// CopyFiles creates a ZIP archive of the given files and streams it to the server using the Copy
// method. No temporary ZIP archive is created on disk. It's all streamed.
func (c *Client) CopyFiles(files []string, id string) error {
	zipReader, err := createZipReader(files)
	if err != nil {
		return err
	}
	return c.Copy(zipReader, id)
}

// Paste reads the file with the given id from the server and writes it to writer.
func (c *Client) Paste(writer io.Writer, id string) error {
	client, err := c.newHTTPClient(nil)
	if err != nil {
		return err
	}

	path := fmt.Sprintf(clipboardPathFormat, id)
	url := fmt.Sprintf("https://%s%s", c.config.ServerAddr, path)
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
		return &errHTTPNotOK{resp.StatusCode, resp.Status}
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
	if err := extractToDir(tmpFile.Name(), dir); err != nil {
		return err
	}
	return nil
}

// Info queries the server for information (password salt, advertised address) required during the
// join operation. This method will first attempt to securely connect over HTTPS, and (if that fails)
// fall back to skipping certificate verification. In the latter case, it will download and return
// the server certificate so the client can pin them.
func (c *Client) Info() (*ServerInfo, error) {
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

	var salt []byte
	if info.Salt != "" {
		salt, err = base64.StdEncoding.DecodeString(info.Salt)
		if err != nil {
			return nil, err
		}
	}

	return &ServerInfo{
		ServerAddr: info.ServerAddr,
		Salt:       salt,
		Cert:       cert,
	}, nil
}

// Verify verifies that the given key (derived from the user password) is in fact correct
// by calling the server's verify endpoint. If the call fails, the key is assumed to be incorrect.
func (c *Client) Verify(cert *x509.Certificate, key *Key) error {
	client, err := c.newHTTPClient(cert)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/verify", c.config.ServerAddr)
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
		return &errHTTPNotOK{resp.StatusCode, resp.Status}
	}

	return nil
}

func (c *Client) addAuthHeader(req *http.Request, key *Key) error {
	if key == nil {
		key = c.config.Key
	}
	if key == nil {
		return nil // No auth configured
	}

	auth, err := GenerateAuthHMAC(key.Bytes, req.Method, req.URL.Path, noAuthRequestAge) // RequestURI is empty!
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", auth)
	return nil
}

func (c *Client) withProgressReader(reader io.ReadCloser, total int64) io.ReadCloser {
	if c.config.ProgressFunc != nil {
		return newProgressReader(reader, total, c.config.ProgressFunc)
	}
	return reader
}

func (c *Client) retrieveInfo(client *http.Client) (*infoResponse, error) {
	resp, err := client.Get(fmt.Sprintf("https://%s/info", c.config.ServerAddr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	info := &infoResponse{}
	if err := json.NewDecoder(resp.Body).Decode(info); err != nil {
		return nil, err
	}

	return info, nil
}

// retrieveCert opens a raw TLS connection and retrieves the leaf certificate
func (c *Client) retrieveCert() (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", c.config.ServerAddr, &tls.Config{
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
		return c.newHTTPClientWithPinnedCert(cert)
	} else if c.config.CertFile != "" {
		cert, err := LoadCertFromFile(c.config.CertFile)
		if err != nil {
			return nil, err
		}
		return c.newHTTPClientWithPinnedCert(cert)
	} else {
		return &http.Client{}, nil
	}
}

func (c *Client) newHTTPClientWithPinnedCert(pinned *x509.Certificate) (*http.Client, error) {
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

var errMissingServerAddr = errors.New("server address missing")
var errResponseBodyEmpty = errors.New("response body was empty")
var errNoPeerCert = errors.New("no peer cert found")
var errNoTrustedCertMatch = errors.New("no trusted cert matches")

type errHTTPNotOK struct {
	code   int
	status string
}

func (e errHTTPNotOK) Error() string {
	return fmt.Sprintf("http: %s", e.status)
}
