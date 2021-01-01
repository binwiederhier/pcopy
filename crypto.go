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
	"regexp"
	"time"
)

const (
	keyLenBytes      = 32
	keyDerivIter     = 10000
	keySaltLenBytes  = 10
	certNotBeforeAge = -time.Hour * 24 * 7      // ~ 1 week
	certNotAfterAge  = time.Hour * 24 * 365 * 3 // ~ 3 years
)

// GenerateKey generates a new random salt and then derives a key from the given password using
// the DeriveKey function. This function is meant to be used when a new server is set up.
func GenerateKey(password []byte) (*Key, error) {
	salt := make([]byte, keySaltLenBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return DeriveKey(password, salt), nil
}

// DeriveKey derives a key using PBKDF2 from the given password, using the given salt. This function
// can be used to derive and then verify a key from a kkown salt and password.
func DeriveKey(password []byte, salt []byte) *Key {
	return &Key{
		Bytes: pbkdf2.Key(password, salt, keyDerivIter, keyLenBytes, sha256.New),
		Salt:  salt,
	}
}

// EncodeKey encodes the raw key and salt into a string in the format SALT:KEY, with both parts
// being base64 encoded.
func EncodeKey(key *Key) string {
	if key == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s", base64.StdEncoding.EncodeToString(key.Salt),
		base64.StdEncoding.EncodeToString(key.Bytes))
}

// DecodeKey decodes a key that was previously encoded with the EncodeKey function.
func DecodeKey(s string) (*Key, error) {
	re := regexp.MustCompile(`^([^:]+):(.+)$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return nil, errInvalidKeyFormat
	}
	rawSalt, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		return nil, errInvalidKeyFormat
	}
	rawKey, err := base64.StdEncoding.DecodeString(matches[2])
	if err != nil {
		return nil, errInvalidKeyFormat
	}
	if len(rawKey) != keyLenBytes {
		return nil, errInvalidKeyFormat
	}
	if len(rawSalt) != keySaltLenBytes {
		return nil, errInvalidKeyFormat
	}
	return &Key{
		Bytes: rawKey,
		Salt:  rawSalt,
	}, nil
}

// EncodeCerts encodes a list of X.509 certificates as PEM.
func EncodeCerts(certs []*x509.Certificate) ([]byte, error) {
	var b bytes.Buffer
	for _, cert := range certs {
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

// LoadCertsFromFile loads PEM-encoded certificates from the given filename.
func LoadCertsFromFile(filename string) ([]*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
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

// GenerateAuthHMAC generates the HMAC auth header used to authorize uthenticate against the server.
// The result can be used in the HTTP "Authorization" header. If the TTL is non-zero, the authorization
// header will only be valid for the given duration.
func GenerateAuthHMAC(key []byte, method string, path string, ttl time.Duration) (string, error) {
	timestamp := time.Now().Unix()
	ttlSecs := int(ttl.Seconds())
	data := []byte(fmt.Sprintf("%d:%d:%s:%s", timestamp, ttlSecs, method, path))
	hash := hmac.New(sha256.New, key)
	if _, err := hash.Write(data); err != nil {
		return "", err
	}

	hashBase64 := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf(authHmacFormat, timestamp, ttlSecs, hashBase64), nil
}

// GenerateKeyAndCert generates a ECDSA P-256 key, and a self-signed certificate.
// It returns both as PEM-encoded values.
func GenerateKeyAndCert() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", err
	}

	cert := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: certCommonName},
		DNSNames:     []string{certCommonName},
		NotBefore:    time.Now().Add(certNotBeforeAge),
		NotAfter:     time.Now().Add(certNotAfterAge),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	out := &bytes.Buffer{}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}
	pemCert := out.String()

	out.Reset()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return "", "", err
	}
	pemKey := out.String()

	return pemKey, pemCert, nil
}

var errInvalidKeyFormat = errors.New("invalid key format")
