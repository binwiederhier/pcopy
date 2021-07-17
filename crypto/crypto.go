// Package crypto provides cryptography functions for generating keys and certificates,
// deriving keys, calculating HMACs and such
package crypto

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
	// KeyLenBytes is a constant that defines the length of the key that is derived from the password (128-bit)
	KeyLenBytes = 32

	// KeyDerivIter is the number of PBKDF2 iterations used to derive the key from the password
	KeyDerivIter = 10000

	keySaltLenBytes  = 10
	certNotBeforeAge = -time.Hour * 24 * 7      // ~ 1 week
	certNotAfterAge  = time.Hour * 24 * 365 * 3 // ~ 3 years

	// TODO move hmac validation in this package as well
	authHmacFormat = "HMAC %d %d %s" // timestamp ttl b64-hmac
)

// Key defines the symmetric key that is derived from the user password. It consists of the raw key bytes
// and the randomly generated salt.
type Key struct {
	Bytes []byte
	Salt  []byte
}

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
		Bytes: pbkdf2.Key(password, salt, KeyDerivIter, KeyLenBytes, sha256.New),
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
	if len(rawKey) != KeyLenBytes {
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

// EncodeCert encodes a X.509 certificates as PEM.
func EncodeCert(cert *x509.Certificate) ([]byte, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// LoadCertFromFile loads the first PEM-encoded certificate from the given filename
func LoadCertFromFile(filename string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
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
			return cert, nil
		}
		b = rest
	}
	return nil, errNoCertFound
}

// CalculatePublicKeyHash calculates the SHA-256 hash of the DER PKIX representation of the public
// key contained in the given certificate. This is useful to use with the --pinnedpubkey option in curl.
func CalculatePublicKeyHash(cert *x509.Certificate) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	hash.Write(der)
	return hash.Sum(nil), nil
}

// EncodeCurlPinnedPublicKeyHash encodes a public key hash in the format that curl's --pinnedpubkey option expects.
func EncodeCurlPinnedPublicKeyHash(hash []byte) string {
	return fmt.Sprintf("sha256//%s", base64.StdEncoding.EncodeToString(hash))
}

// ReadCurlPinnedPublicKeyFromFile reads a cert from the given filename and calculates the public key for curl
func ReadCurlPinnedPublicKeyFromFile(filename string) (string, error) {
	cert, err := LoadCertFromFile(filename)
	if err != nil {
		return "", err
	}
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		hash, err := CalculatePublicKeyHash(cert)
		if err != nil {
			return "", err
		}
		return EncodeCurlPinnedPublicKeyHash(hash), nil
	}
	return "", nil
}

// GenerateAuthHMAC generates the HMAC auth header used to authorize uthenticate against the server.
// The result can be used in the HTTP "Authorization" header. If the TTL is non-zero, the authorization
// header will only be valid for the given duration.
func GenerateAuthHMAC(key []byte, method string, path string, ttl time.Duration) (string, error) {
	return generateAuthHMAC(time.Now().Unix(), key, method, path, ttl)
}

func generateAuthHMAC(timestamp int64, key []byte, method string, path string, ttl time.Duration) (string, error) {
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
func GenerateKeyAndCert(hostname string) (string, string, error) {
	key, cert, err := generateKeyAndCertRaw(hostname)
	if err != nil {
		return "", "", err
	}
	pemKey, err := encodeKey(key)
	if err != nil {
		return "", "", err
	}
	pemCert, err := EncodeCert(cert)
	if err != nil {
		return "", "", err
	}
	return string(pemKey), string(pemCert), nil
}

func generateKeyAndCertRaw(hostname string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(certNotBeforeAge),
		NotAfter:     time.Now().Add(certNotAfterAge),
	}
	derCert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var errInvalidKeyFormat = errors.New("invalid key format")
var errNoCertFound = errors.New("no cert found in file")
