package pcopy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"os"
	"path/filepath"
)

const keyLen = 32
const saltLen = 10
const pbkdfIter = 10000

func DeriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, pbkdfIter, keyLen, sha256.New)
}

func EncodeKey(key []byte, salt []byte) string {
	return fmt.Sprintf("%s:%s", base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(key))
}

func GenKey(password []byte) (string, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return EncodeKey(DeriveKey(password, salt), salt), nil
}

func GetExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	realpath, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}

	return realpath, nil
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