package pcopy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"regexp"
	"time"
)

const keyLen = 32
const saltLen = 10
const pbkdfIter = 10000

func DeriveKey(password []byte, salt []byte) *Key {
	return &Key{
		Bytes: pbkdf2.Key(password, salt, pbkdfIter, keyLen, sha256.New),
		Salt: salt,
	}
}

func EncodeKey(key *Key) string {
	if key == nil {
		return ""
	} else {
		return fmt.Sprintf("%s:%s", base64.StdEncoding.EncodeToString(key.Salt),
			base64.StdEncoding.EncodeToString(key.Bytes))
	}
}

func DecodeKey(keyEncoded string) (*Key, error) {
	re := regexp.MustCompile(`^([^:]+):(.+)$`)
	matches := re.FindStringSubmatch(keyEncoded)
	if matches == nil {
		return nil, errors.New("invalid key")
	}
	rawSalt, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		return nil, errors.New("invalid key, cannot decode salt")
	}
	rawKey, err := base64.StdEncoding.DecodeString(matches[2])
	if err != nil {
		return nil, errors.New("invalid key, cannot decode")
	}
	return &Key{
		Bytes: rawKey,
		Salt: rawSalt,
	}, nil
}

func GenerateKey(password []byte) (*Key, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return DeriveKey(password, salt), nil
}

func EncodeCerts(certs []*x509.Certificate) ([]byte, error) {
	var b bytes.Buffer
	for _, cert := range certs {
		err := pem.Encode(&b, &pem.Block{
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func LoadCertsFromFile(file string) ([]*x509.Certificate, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0)
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		b = rest
	}
	return certs, nil
}

func GenerateAuthHMAC(key []byte, method string, path string) (string, error) {
	timestamp := time.Now().Unix()
	data := []byte(fmt.Sprintf("%d:%s:%s", timestamp, method, path))
	hash := hmac.New(sha256.New, key)
	if _, err := hash.Write(data); err != nil {
		return "", err
	}

	hashBase64 := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf("HMAC v1 %d %s", timestamp, hashBase64), nil
}
