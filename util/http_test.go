package util

import (
	"crypto/x509"
	"encoding/pem"
	"heckel.io/pcopy/test"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPClientWithPinnedCert_Success(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is a test"))
	}))
	defer server.Close()

	client, _ := NewHTTPClientWithPinnedCert(server.Certificate())
	resp, _ := client.Get(server.URL)
	b, _ := io.ReadAll(resp.Body)
	test.StrEquals(t, "this is a test", string(b))
}

func TestNewHTTPClientWithPinnedCert_Failure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("This should not be called")
	}))
	defer server.Close()

	wrongCertBlock, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`))
	wrongCert, _ := x509.ParseCertificate(wrongCertBlock.Bytes)

	client, _ := NewHTTPClientWithPinnedCert(wrongCert)
	_, err := client.Get(server.URL)
	if err == nil {
		t.Fatal("expected error, got none")
	}
}