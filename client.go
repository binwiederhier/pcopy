package pcopy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	config *Config
}

type Info struct {
	Certs []*x509.Certificate
	Salt  []byte
}

type infoResponse struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`
}

func NewClient(config *Config) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, missingServerAddrError
	}
	return &Client{
		config: config,
	}, nil
}

func (c *Client) Copy(reader io.Reader, fileId string) error {
	client, err := c.newHttpClient(nil)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/clip/%s", c.config.ServerAddr, fileId)
	req, err := http.NewRequest(http.MethodPut, url, reader)
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
		return errors.New(resp.Status)
	}

	return nil
}

func (c *Client) Paste(writer io.Writer, fileId string) error {
	client, err := c.newHttpClient(nil)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/clip/%s", c.config.ServerAddr, fileId)
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
		return errors.New("response body was empty")
	} else if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}

	return nil
}

func (c *Client) Info() (*Info, error) {
	var certs []*x509.Certificate
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
		certs, err = c.retrieveCerts()
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

	return &Info{
		Salt:  salt,
		Certs: certs,
	}, nil
}


func (c *Client) Verify(certs []*x509.Certificate, key *Key) error {
	client, err := c.newHttpClient(certs)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/verify", c.config.ServerAddr)
	req, err := http.NewRequest(http.MethodPut, url, nil)
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
		return errors.New(resp.Status)
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

	auth, err := GenerateAuthHMAC(key.Bytes, req.Method, req.URL.Path) // RequestURI is empty!
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", auth)
	return nil
}

func (c *Client) retrieveInfo(client *http.Client) (*infoResponse, error) {
	resp, err := client.Get(fmt.Sprintf("https://%s/", c.config.ServerAddr))
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

func (c *Client) retrieveCerts() ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", c.config.ServerAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

func (c *Client) newHttpClient(certs []*x509.Certificate) (*http.Client, error) {
	if certs != nil {
		return c.newHttpClientWithRootCAs(certs)
	} else if c.config.CertFile != "" {
		certs, err := LoadCertsFromFile(c.config.CertFile)
		if err != nil {
			return nil, err
		}
		return c.newHttpClientWithRootCAs(certs)
	} else {
		return &http.Client{}, nil
	}
}

func (c *Client) newHttpClientWithRootCAs(certs []*x509.Certificate) (*http.Client, error) {
	rootCAs := x509.NewCertPool()
	for _, cert := range certs {
		rootCAs.AddCert(cert)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
				ServerName: "pcopy",
			},
		},
	}, nil
}

var missingServerAddrError = errors.New("server address missing")