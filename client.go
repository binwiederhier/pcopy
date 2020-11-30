package pcopy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type Client struct {
	config *Config
}

type Info struct {
	Cert string
	Salt []byte
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
	client, err := c.newHttpClient()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/clip/%s", c.config.ServerAddr, fileId)
	req, err := http.NewRequest(http.MethodPut, url, reader)
	if err != nil {
		return err
	}

	if _, err := client.Do(req); err != nil {
		return err
	}

	return nil
}

func (c *Client) Paste(writer io.Writer, fileId string) error {
	client, err := c.newHttpClient()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/clip/%s", c.config.ServerAddr, fileId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	} else if resp.Body == nil {
		return errors.New("response body was empty")
	}

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}

	return nil
}


func (c *Client) Join() (string, error) {
	return c.retrieveCert()
}

func (c *Client) Info() (*Info, error) {
	cert := ""

	// First attempt to retrieve info with secure HTTP client
	info, err := c.getInfo(&http.Client{})
	if err != nil {
		fmt.Printf("Warning: remote cert invalid: %s; will be pinned\n", err.Error())

		// Then attempt to retrieve ignoring bad certs (this is okay, we pin the cert if it's bad)
		insecureTransport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		insecureClient := &http.Client{Transport: insecureTransport}
		info, err = c.getInfo(insecureClient)
		if err != nil {
			return nil, err
		}

		// Retrieve bad cert for cert pinning
		cert, err = c.retrieveCert()
		if err != nil {
			return nil, err
		}
	}

	salt, err := base64.StdEncoding.DecodeString(info.Salt)
	if err != nil {
		return nil, err
	}

	return &Info{
		Salt: salt,
		Cert: cert,
	}, nil
}

func (c *Client) getInfo(client *http.Client) (*infoResponse, error) {
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

func (c *Client) retrieveCert() (string, error) {
	conn, err := tls.Dial("tcp", c.config.ServerAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func (c *Client) newHttpClient() (*http.Client, error) {
	if c.config.CertFile != "" {
		return c.newHttpClientWithExtraCert()
	} else {
		return &http.Client{}, nil
	}
}

// From https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
func (c *Client) newHttpClientWithExtraCert() (*http.Client, error) {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	certs, err := ioutil.ReadFile(c.config.CertFile)
	if err != nil {
		log.Fatalf("Failed to append %q to RootCAs: %v", c.config.CertFile, err)
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, errors.New("no certs appended, using system certs only")
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




