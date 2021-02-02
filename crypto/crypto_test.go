package crypto

import (
	"bytes"
	"heckel.io/pcopy/test"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey([]byte("some password"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key.Bytes) != KeyLenBytes {
		t.Fatalf("expected key to be %d bytes, got %d", KeyLenBytes, len(key.Bytes))
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
	salt := test.FromBase64(t, "Osz6osE1fRRirA==")
	key := DeriveKey(pass, salt)
	expectedKey := test.FromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I=")
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
		Salt:  test.FromBase64(t, "Osz6osE1fRRirA=="),
		Bytes: test.FromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I="),
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
	expectedSalt := test.FromBase64(t, "Osz6osE1fRRirA==")
	expectedKey := test.FromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I=")
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
	test.StrEquals(t, "sha256//Z0tCCalbcr2Y9+UXq9p72cwGhodTUaptkHUfuy1fvCs=", EncodeCurlPinnedPublicKeyHash(hash))
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

func TestGenerateKeyAndCert(t *testing.T) {
	dir := t.TempDir()
	key, cert, err := GenerateKeyAndCert("thiscert.com")
	if err != nil {
		t.Fatal(err)
	}

	test.StrContains(t, key, "--BEGIN EC PRIVATE KEY--")
	test.StrContains(t, cert, "--BEGIN CERTIFICATE--")

	certfile := filepath.Join(dir, "cert")
	ioutil.WriteFile(certfile, []byte(cert), 0600)

	crt, _ := LoadCertFromFile(certfile)
	test.BytesEquals(t, crt.RawIssuer, crt.RawSubject) // self-signed
	test.StrEquals(t, "thiscert.com", crt.Subject.CommonName)
	test.StrEquals(t, "thiscert.com", crt.DNSNames[0])
}

func TestEncodeCertAndReadCurlPinnedPublicKeyFromFileSuccess(t *testing.T) {
	dir := t.TempDir()
	serv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi there what's up"))
	}))
	defer serv.Close()

	cert, err := EncodeCert(serv.Certificate())
	if err != nil {
		t.Fatal(err)
	}

	certfile := filepath.Join(dir, "cert")
	ioutil.WriteFile(certfile, cert, 0600)

	pin, err := ReadCurlPinnedPublicKeyFromFile(certfile)
	if err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	curl := exec.Command("curl", "-k", "--pinnedpubkey", pin, serv.URL)
	curl.Stdout = &stdout
	curl.Run()

	test.StrEquals(t, "hi there what's up", stdout.String())
}

func TestReadCurlPinnedPublicKeyFromFileFileNotExist(t *testing.T) {
	_, err := ReadCurlPinnedPublicKeyFromFile("this is not a file")
	if err == nil {
		t.Fatalf("expected error, but got none")
	}
}

func TestReadCurlPinnedPublicKeyFromFileWithCertThatIsNotSelfSigned(t *testing.T) {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIF4zCCBMugAwIBAgIQBd1cTBm5RiKX80472UKbLzANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz
dXJhbmNlIFNlcnZlciBDQTAeFw0yMDEyMjAwMDAwMDBaFw0yMTAzMTkyMzU5NTla
MGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRMwEQYDVQQHEwpN
ZW5sbyBQYXJrMRcwFQYDVQQKEw5GYWNlYm9vaywgSW5jLjEXMBUGA1UEAwwOKi53
aGF0c2FwcC5uZXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATK7dKJhnZ1jmOp
bdGR2B7aetASAzys2kN8h3NIJBEmymCm/tqVBKKuXGE8AT/XgyXzT9KdIw5vFLfi
9L3UkxgEo4IDSTCCA0UwHwYDVR0jBBgwFoAUUWj/kK8CB3U8zNllZGKiErhZcjsw
HQYDVR0OBBYEFEZegGEK8zjD7je5GdCZsF5RJ44eMHQGA1UdEQRtMGuCEiouY2Ru
LndoYXRzYXBwLm5ldIISKi5zbnIud2hhdHNhcHAubmV0gg4qLndoYXRzYXBwLmNv
bYIOKi53aGF0c2FwcC5uZXSCBXdhLm1lggx3aGF0c2FwcC5jb22CDHdoYXRzYXBw
Lm5ldDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMHUGA1UdHwRuMGwwNKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9z
aGEyLWhhLXNlcnZlci1nNi5jcmwwNKAyoDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
LmNvbS9zaGEyLWhhLXNlcnZlci1nNi5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1s
AQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAI
BgZngQwBAgIwgYMGCCsGAQUFBwEBBHcwdTAkBggrBgEFBQcwAYYYaHR0cDovL29j
c3AuZGlnaWNlcnQuY29tME0GCCsGAQUFBzAChkFodHRwOi8vY2FjZXJ0cy5kaWdp
Y2VydC5jb20vRGlnaUNlcnRTSEEySGlnaEFzc3VyYW5jZVNlcnZlckNBLmNydDAM
BgNVHRMBAf8EAjAAMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHUA9lyUL9F3MCIU
VBgIMJRWjuNNExkzv98MLyALzE7xZOMAAAF2f7O0lQAABAMARjBEAiB8SP+iwKHp
f5DhUpMESLYU2XPzadrX1WqMQ3I/Lw4oBgIgICU99XaGxRr/Y8UXydBnv9cFZZII
uf+0C12/ZunISWwAdgBc3EOS/uarRUSxXprUVuYQN/vV+kfcoXOUsl7m9scOygAA
AXZ/s7T7AAAEAwBHMEUCIQDjN7e31uiY6LliNXJj+pMn9q+VhQQZc4ipYrIbcCqA
xwIgIfvdH68/ocuvHYRii9xE/rsXReC4Hk46w7Jga5ZlMHIwDQYJKoZIhvcNAQEL
BQADggEBAGFXK4w5LapNCCJEOLcWODrw4gEFe+S/TItnM0ur4A2F/E2ysmyNimZF
X3IFvbOAnJVgtsaTrb1yB+xaM6cd1u9EOUsD/uY7pbjPM4hHK7mTQ+nJUbUuSE5n
RwsjqS+eGcNlfiUmbSl5Fg+APYWzNBs39naReCU/mzmxjcWj6U3XyGm2oPwcxosY
XAFG9lfy1/3XhNRy4lAZf1RGVhnxP7xjz2jsHWDJVLWPWkuohYsDcdkKh5wPAuqA
RPoma5tY3PHdm7Qt0ZwMrjgv0oMP3abSL//SJ0Xrg6G2sJq9KfBnkGGsX3GQFHt/
eTzmbC8o65uD4keYyszxUIk8bBPGM74=
-----END CERTIFICATE-----`)

	certfile := filepath.Join(t.TempDir(), "cert")
	ioutil.WriteFile(certfile, cert, 0600)

	pin, _ := ReadCurlPinnedPublicKeyFromFile("this is not a file")
	test.StrEquals(t, "", pin)
}
