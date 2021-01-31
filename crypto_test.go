package pcopy

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey([]byte("some password"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key.Bytes) != keyLenBytes {
		t.Fatalf("expected key to be %d bytes, got %d", keyLenBytes, len(key.Bytes))
	}
	if len(key.Salt) != keySaltLenBytes {
		t.Fatalf("expected salt to be %d bytes, got %d", keySaltLenBytes, len(key.Salt))
	}
}

func TestDeriveKey_1(t *testing.T) {
	pass := []byte("some password")
	salt := []byte("10 bytes..")
	key := DeriveKey(pass, salt)
	expectedKey := []byte{0xd7, 0xf7, 0x7a, 0x2a, 0xc9, 0xb6, 0xb6, 0x5c, 0xa9, 0x75, 0x4b, 0x68, 0x0e, 0xa3, 0x1f, 0x47,
		0xe1, 0xab, 0x2a, 0x55, 0x1a, 0x0f, 0x98, 0x3b, 0x85, 0xce, 0xce, 0x33, 0x65, 0xee, 0x02, 0x51}
	expectedSalt := salt
	if !bytes.Equal(key.Bytes, expectedKey) {
		t.Fatalf("expected salt to be %x, got %x", expectedKey, key.Bytes)
	}
	if !bytes.Equal(key.Salt, expectedSalt) {
		t.Fatalf("expected salt to be %x, got %x", expectedSalt, key.Salt)
	}
}

func TestDeriveKey_2(t *testing.T) {
	pass := []byte("test password")
	salt := fromBase64(t, "Osz6osE1fRRirA==")
	key := DeriveKey(pass, salt)
	expectedKey := fromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I=")
	expectedSalt := salt
	if !bytes.Equal(key.Bytes, expectedKey) {
		t.Fatalf("expected salt to be %x, got %x", expectedKey, key.Bytes)
	}
	if !bytes.Equal(key.Salt, expectedSalt) {
		t.Fatalf("expected salt to be %x, got %x", expectedSalt, key.Salt)
	}
}

func TestEncodeKey_NonNil(t *testing.T) {
	key := &Key{
		Salt:  fromBase64(t, "Osz6osE1fRRirA=="),
		Bytes: fromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I="),
	}
	expected := "Osz6osE1fRRirA==:XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I="
	actual := EncodeKey(key)
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestEncodeKey_Nil(t *testing.T) {
	actual := EncodeKey(nil)
	if actual != "" {
		t.Fatalf("expected empty string, got %s", actual)
	}
}

func TestDecodeKey_Success(t *testing.T) {
	keyEncoded := "Osz6osE1fRRirA==:XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I="
	key, err := DecodeKey(keyEncoded)
	if err != nil {
		t.Fatal(err)
	}
	expectedSalt := fromBase64(t, "Osz6osE1fRRirA==")
	expectedKey := fromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I=")
	if !bytes.Equal(key.Bytes, expectedKey) {
		t.Fatalf("expected salt to be %x, got %x", expectedKey, key.Bytes)
	}
	if !bytes.Equal(key.Salt, expectedSalt) {
		t.Fatalf("expected salt to be %x, got %x", expectedSalt, key.Salt)
	}
}

func TestDecodeKey_FailureInvalidFormat(t *testing.T) {
	keyEncoded := "this is invalid"
	_, err := DecodeKey(keyEncoded)
	if err != errInvalidKeyFormat {
		t.Fatalf("expected errInvalidKeyFormat, but got no error")
	}
}

func TestDecodeKey_FailureSaltTooShort(t *testing.T) {
	keyEncoded := "ZGRzcwo=:XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I="
	_, err := DecodeKey(keyEncoded)
	if err != errInvalidKeyFormat {
		t.Fatalf("expected errInvalidKeyFormat, but got no error")
	}
}

func TestDecodeKey_FailureKeyTooShort(t *testing.T) {
	keyEncoded := "Osz6osE1fRRirA==:ZnNkZnNmCg=="
	_, err := DecodeKey(keyEncoded)
	if err != errInvalidKeyFormat {
		t.Fatalf("expected errInvalidKeyFormat, but got no error")
	}
}

func TestDecodeKey_FailureInvalidBase64(t *testing.T) {
	keyEncoded := "this is:invalid"
	_, err := DecodeKey(keyEncoded)
	if err != errInvalidKeyFormat {
		t.Fatalf("expected errInvalidKeyFormat, but got no error")
	}
}

func TestDecodeKey_FailureKeyInvalidBase64(t *testing.T) {
	keyEncoded := "Osz6osE1fRRirA==:this is invalid"
	_, err := DecodeKey(keyEncoded)
	if err != errInvalidKeyFormat {
		t.Fatalf("expected errInvalidKeyFormat, but got no error")
	}
}

func TestLoadCertFromFileAndCalculatePublicKeyHash_Success(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
MIIBMzCB2aADAgECAhED/nPE4UooT9Ru76nApxRWWzAKBggqhkjOPQQDAjAQMQ4w
DAYDVQQDEwVwY29weTAeFw0yMDEyMzExNzI2NTVaFw0yNDAxMDcxNzI2NTVaMBAx
DjAMBgNVBAMTBXBjb3B5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElTj8jvwg
HVAkTkgZc3PqVIpUVmu60wKcxWU3ht+7ucjOU51p3yWZgsoc2Dk4NiPg5CoIFmZl
P7sonn6ZVCBzKqMUMBIwEAYDVR0RBAkwB4IFcGNvcHkwCgYIKoZIzj0EAwIDSQAw
RgIhAMp7oFxtc93HbfkdhtlBBibc0AJw1tnSYOj+nGbPlxX/AiEA64WsMewc29LT
1FfIV4ULTMxTwgV6M6b6vmPJEHYfkRU=
-----END CERTIFICATE-----`
	filename := filepath.Join(t.TempDir(), "cert.crt")
	ioutil.WriteFile(filename, []byte(pemCert), 0700)

	cert, err := LoadCertFromFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := CalculatePublicKeyHash(cert)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "sha256//Z0tCCalbcr2Y9+UXq9p72cwGhodTUaptkHUfuy1fvCs=", EncodeCurlPinnedPublicKeyHash(hash))
}

func TestLoadCertFromFile_FileDoesNotExist(t *testing.T) {
	_, err := LoadCertFromFile("/not/a/file")
	if err == nil {
		t.Fatalf("expected error, but got none")
	}
}

func TestLoadCertFromFile_FailureNoCert(t *testing.T) {
	pemCert := `-----NOT A CERT-----
MIIBMzCB2aADAgECAhED/nPE4UooT9Ru76nApxRWWzAKBggqhkjOPQQDAjAQMQ4w
DAYDVQQDEwVwY29weTAeFw0yMDEyMzExNzI2NTVaFw0yNDAxMDcxNzI2NTVaMBAx
DjAMBgNVBAMTBXBjb3B5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElTj8jvwg
HVAkTkgZc3PqVIpUVmu60wKcxWU3ht+7ucjOU51p3yWZgsoc2Dk4NiPg5CoIFmZl
P7sonn6ZVCBzKqMUMBIwEAYDVR0RBAkwB4IFcGNvcHkwCgYIKoZIzj0EAwIDSQAw
RgIhAMp7oFxtc93HbfkdhtlBBibc0AJw1tnSYOj+nGbPlxX/AiEA64WsMewc29LT
1FfIV4ULTMxTwgV6M6b6vmPJEHYfkRU=
-----NOT A CERT-----`
	filename := filepath.Join(t.TempDir(), "cert.crt")
	ioutil.WriteFile(filename, []byte(pemCert), 0700)

	_, err := LoadCertFromFile(filename)
	if err != errNoCertFound {
		t.Fatalf("expected errNoCertFound, but got %s", err)
	}
}

func fromBase64(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
