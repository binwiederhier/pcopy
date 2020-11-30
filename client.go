package pcopy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

var _ Client = &client{}

type client struct {
	config *Config
}

func NewClient(config *Config) Client {
	return &client{
		config: config,
	}
}

func (c *client) Copy(reader io.Reader, fileId string) error {
	client, err := c.newHttpClient()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/%s", c.config.ServerAddr, fileId)
	req, err := http.NewRequest(http.MethodPut, url, reader)
	if err != nil {
		return err
	}

	if _, err := client.Do(req); err != nil {
		return err
	}

	return nil
}

func (c *client) Paste(writer io.Writer, fileId string) error {
	client, err := c.newHttpClient()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/%s", c.config.ServerAddr, fileId)
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


func (c *client) Join() (string, error) {
	return c.retrieveCert()
}

func (c *client) retrieveCert() (string, error) {
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

// From https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
func (c *client) newHttpClient() (*http.Client, error) {
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




