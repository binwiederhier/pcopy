package pcopy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"math/big"
	"os"
	"regexp"
	"strings"
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
	return fmt.Sprintf("HMAC %d %s", timestamp, hashBase64), nil
}

func GenerateKeyAndCert() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return "", "", nil
	}
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: certCommonName},
		DNSNames: []string{certCommonName},
		NotBefore: time.Now().Add(-time.Hour * 24 * 7),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 3),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return "", "", nil
	}

	out := &bytes.Buffer{}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", nil
	}
	pemCert := out.String()

	out.Reset()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", nil
	}
	if err := pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return "", "", nil
	}
	pemKey := out.String()

	return pemKey, pemCert, nil
}

func ExpandHome(path string) string {
	return os.ExpandEnv(strings.ReplaceAll(path, "~", "$HOME"))
}

func CollapseHome(path string) string {
	home := os.Getenv("HOME")
	if home != "" && strings.HasPrefix(path, home) {
		return fmt.Sprintf("~%s", strings.TrimPrefix(path, home))
	} else {
		return path
	}
}

// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
func BytesToHuman(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}
