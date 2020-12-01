package pcopy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
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

func NewClient(config *Config) *Client {
	return &Client{
		config: config,
	}
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

	salt, err := base64.StdEncoding.DecodeString(info.Salt)
	if err != nil {
		return nil, err
	}

	return &Info{
		Salt:  salt,
		Certs: certs,
	}, nil
}


func (c *Client) Verify(certs []*x509.Certificate, key []byte) error {
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

func (c *Client) addAuthHeader(req *http.Request, key []byte) error {
	if key == nil {
		key = c.config.Key
	}

	timestamp := time.Now().Unix()
	data := []byte(fmt.Sprintf("%d:%s:%s", timestamp, req.Method, req.URL.Path)) // RequestURI is empty!
	hash := hmac.New(sha256.New, key)
	if _, err := hash.Write(data); err != nil {
		return err
	}

	hashBase64 := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	req.Header.Set("Authorization", fmt.Sprintf("HMAC v1 %d %s", timestamp, hashBase64))

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
		cert, err := c.readCertFromFile(c.config.CertFile)
		if err != nil {
			return nil, err
		}
		return c.newHttpClientWithRootCAs([]*x509.Certificate{cert})
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

func (c *Client) readCertFromFile(certFile string) (*x509.Certificate, error) {
	pemCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemCert)
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}



