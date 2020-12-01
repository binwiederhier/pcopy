package pcopy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
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
