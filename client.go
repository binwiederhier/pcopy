package pcopy

import (
	"archive/zip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Client struct {
	config *Config
}

func NewClient(config *Config) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, missingServerAddrError
	}
	return &Client{
		config: config,
	}, nil
}

func (c *Client) Copy(reader io.ReadCloser, id string) error {
	client, err := c.newHttpClient(nil)
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
		return errors.New(resp.Status)
	}

	return nil
}

func (c *Client) CopyFiles(files []string, id string) error {
	return c.Copy(c.createZipReader(files), id)
}

func (c *Client) Paste(writer io.Writer, id string) error {
	client, err := c.newHttpClient(nil)
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
		return errors.New("response body was empty")
	} else if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
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

func (c *Client) PasteFiles(dir string, id string) error {
	// From: https://golangcode.com/unzip-files-in-go/

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile, err := ioutil.TempFile(dir, ".pcopy-paste.*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	f, err := os.OpenFile(tmpFile.Name(), os.O_RDWR | os.O_TRUNC, 0700)
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

	z, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return err
	}
	defer z.Close()

	for _, zf := range z.File {
		filename := filepath.Join(dir, zf.Name)

		if !strings.HasPrefix(filename, filepath.Clean(dir) + string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", filename) // ZipSlip, see https://snyk.io/research/zip-slip-vulnerability#go
		}

		if zf.FileInfo().IsDir() {
			os.MkdirAll(filename, 0755)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			return  err
		}
		outFile, err := os.OpenFile(filename, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, zf.Mode())
		if err != nil {
			return  err
		}
		entry, err := zf.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, entry)
		outFile.Close()
		entry.Close()
		if err != nil {
			return err
		}
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
		ServerAddr: info.ServerAddr,
		Salt:       salt,
		Certs:      certs,
	}, nil
}


func (c *Client) Verify(certs []*x509.Certificate, key *Key) error {
	client, err := c.newHttpClient(certs)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s%s", c.config.ServerAddr, pathVerify)
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
	} else {
		return reader
	}
}

func (c *Client) retrieveInfo(client *http.Client) (*infoResponse, error) {
	resp, err := client.Get(fmt.Sprintf("https://%s%s", c.config.ServerAddr, pathInfo))
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
	serverName := certCommonName
	for _, cert := range certs {
		rootCAs.AddCert(cert)
		if !cert.IsCA {
			if len(cert.DNSNames) > 0 {
				serverName = cert.DNSNames[0]
			} else {
				serverName = cert.Subject.CommonName
			}
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
				ServerName: serverName, // Note: This is checked despite the insecure config
			},
		},
	}, nil
}

func (c *Client) createZipReader(files []string) io.ReadCloser {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		z := zip.NewWriter(pw)
		defer z.Close()

		for _, file := range files {
			stat, err := os.Stat(file)
			if err != nil {
				log.Printf("Skipping file %s due to error: %s\n", file, err.Error())
				continue
			}

			if stat.IsDir() {
				if err := c.addZipDir(z, file); err != nil {
					log.Printf("Skipping directory %s due to error: %s\n", file, err.Error())
					continue
				}
			} else {
				if err := c.addZipFile(z, file, stat); err != nil {
					log.Printf("Skipping file %s due to error: %s\n", file, err.Error())
					continue
				}
			}
		}
	}()

	return pr
}

func (c *Client) addZipFile(z *zip.Writer, file string, stat os.FileInfo) error {
	zf, err := z.CreateHeader(&zip.FileHeader{
		Name: file,
		Modified: stat.ModTime(),
		Method: zip.Deflate,
	})
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(zf, f); err != nil {
		return err
	}
	return nil
}

func (c *Client) addZipDir(z *zip.Writer, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Skipping %s due to error: %s\n", path, err.Error())
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if err := c.addZipFile(z, path, info); err != nil {
			log.Printf("Cannot add %s due to error: %s\n", path, err.Error())
			return nil
		}
		return nil
	})
}

type Info struct {
	ServerAddr string
	Salt       []byte
	Certs      []*x509.Certificate
}

var missingServerAddrError = errors.New("server address missing")