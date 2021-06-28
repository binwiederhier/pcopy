package config

import (
	"fmt"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRawConfig_WithCommentSuccess(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`SomeFlag true
# SomeFlag false`))
	if err != nil {
		t.Fatal(err)
	}
	if config["SomeFlag"] != "true" {
		t.Fatalf("expected %s, got %s", "true", config["SomeFlag"])
	}
}

func TestLoadRawConfig_OverrideSuccess(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`SomeFlag true
SomeFlag false`))
	if err != nil {
		t.Fatal(err)
	}
	if config["SomeFlag"] != "false" {
		t.Fatalf("expected %s, got %s", "false", config["SomeFlag"])
	}
}

func TestLoadRawConfig_TrimTrailingSpaceSuccess(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`SomeFlag "true"    `))
	if err != nil {
		t.Fatal(err)
	}
	if config["SomeFlag"] != `"true"` {
		t.Fatalf("expected %s, got %s", "", config["SomeFlag"])
	}
}

func TestLoadRawConfig_EmptyValue1Success(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`SomeFlag`))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := config["SomeFlag"]; !ok || v != "" {
		t.Fatalf("expected %s, got %s (ok: %t)", "", config["SomeFlag"], ok)
	}
}

func TestLoadRawConfig_EmptyValue2Success(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`SomeFlag   `)) // Trailing spaces on empty value
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := config["SomeFlag"]; !ok || v != "" {
		t.Fatalf("expected %s, got %s (ok: %t)", "", config["SomeFlag"], ok)
	}
}

func TestLoadConfig_EmptyFileSuccess(t *testing.T) {
	config, err := loadConfig(strings.NewReader(``))
	if err != nil {
		t.Fatal(err)
	}
	if config.ClipboardDir != DefaultClipboardDir {
		t.Fatalf("expected %s, got %s", DefaultClipboardDir, config.ClipboardDir)
	}
	if config.ListenHTTPS != fmt.Sprintf(":%d", DefaultPort) {
		t.Fatalf("expected %s, got %s", fmt.Sprintf(":%d", DefaultPort), config.ListenHTTPS)
	}
}

func TestLoadConfig_AllTheThingsSuccess(t *testing.T) {
	dir := t.TempDir()

	// This is a test key, don't freak out!
	pemKey := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHf6DNxfzPdOtM3vw/wW1hTaShp/Z1t0eT7RRak/S39doAoGCCqGSM49
AwEHoUQDQgAEp60xIGJbAUAmUe+KP9KB8ge4B+vJTKnMSctysQnG+fKOCTc9q7EX
xmNBMaTK3zXTdMev+TiCfmljflB7ZTkjTw==
-----END EC PRIVATE KEY-----`
	keyFile := filepath.Join(dir, "key.key")
	ioutil.WriteFile(keyFile, []byte(pemKey), 0700)

	pemCert := `-----BEGIN CERTIFICATE-----
MIIBMjCB2KADAgECAhAmIv+vEcI8iwP/TR4G3MavMAoGCCqGSM49BAMCMBAxDjAM
BgNVBAMTBXBjb3B5MB4XDTIwMTIyMTE2MDE1NVoXDTIzMTIyODE2MDE1NVowEDEO
MAwGA1UEAxMFcGNvcHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASnrTEgYlsB
QCZR74o/0oHyB7gH68lMqcxJy3KxCcb58o4JNz2rsRfGY0ExpMrfNdN0x6/5OIJ+
aWN+UHtlOSNPoxQwEjAQBgNVHREECTAHggVwY29weTAKBggqhkjOPQQDAgNJADBG
AiEA1W0sKuPLyxoW0QTn0jovq9cAzT4IT5HaGeX8Z5rWlE4CIQCGn1yMReAETlWB
D1OY3Axih+rz7mF2xHK20TxRuy1sqw==
-----END CERTIFICATE-----`
	certFile := filepath.Join(dir, "cert.crt")
	ioutil.WriteFile(certFile, []byte(pemCert), 0700)

	config, err := loadConfig(strings.NewReader(fmt.Sprintf(`
ListenAddr :1234
ServerAddr hi.com
DefaultID my-default-id
Key Osz6osE1fRRirA==:XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I=
KeyFile %s
CertFile %s
ClipboardName Phil's Clipboard
ClipboardDir %s
ClipboardSizeLimit 10M
ClipboardCountLimit 101
FileSizeLimit 123k
FileExpireAfter 10d 12d 13d
FileModesAllowed ro rw
`, keyFile, certFile, dir)))
	if err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, ":1234", config.ListenHTTPS)
	test.StrEquals(t, "https://hi.com:2586", config.ServerAddr)
	test.BytesEquals(t, test.FromBase64(t, "Osz6osE1fRRirA=="), config.Key.Salt)
	test.BytesEquals(t, test.FromBase64(t, "XEBZJjB/7w4eCugzQSkwGMe8QW4nbsPvPMlle1wvW4I="), config.Key.Bytes)
	test.StrEquals(t, "my-default-id", config.DefaultID)
	test.StrEquals(t, keyFile, config.KeyFile)
	test.StrEquals(t, certFile, config.CertFile)
	test.StrEquals(t, "Phil's Clipboard", config.ClipboardName)
	test.StrEquals(t, dir, config.ClipboardDir)
	test.Int64Equals(t, 10*1024*1024, config.ClipboardSizeLimit)
	test.Int64Equals(t, 101, int64(config.ClipboardCountLimit))
	test.Int64Equals(t, 123*1024, config.FileSizeLimit)
	test.Int64Equals(t, 10*24, int64(config.FileExpireAfterDefault.Hours()))
	test.Int64Equals(t, 12*24, int64(config.FileExpireAfterNonTextMax.Hours()))
	test.Int64Equals(t, 13*24, int64(config.FileExpireAfterTextMax.Hours()))
	test.StrEquals(t, "ro", config.FileModesAllowed[0])
	test.StrEquals(t, "rw", config.FileModesAllowed[1])
}

func TestConfig_WriteFileAllTheThings(t *testing.T) {
	config := New()
	config.ServerAddr = "some-host.com"
	config.ListenHTTPS = ":8888"
	config.ListenHTTP = ":8889"
	config.DefaultID = "some-id"
	config.Key = &crypto.Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	config.CertFile = "some cert file"
	config.KeyFile = "some key file"
	config.ClipboardName = "Phil's Clipboard"
	config.ClipboardDir = "/tmp/clipboarddir"
	config.ClipboardCountLimit = 1234
	config.ClipboardSizeLimit = 9876
	config.FileSizeLimit = 777
	config.FileExpireAfterDefault = time.Hour
	config.FileExpireAfterNonTextMax = 7 * time.Hour
	config.FileExpireAfterTextMax = 0
	config.FileModesAllowed = []string{"ro", "rw"}

	filename := filepath.Join(t.TempDir(), "some.conf")
	if err := config.WriteFile(filename); err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(b)
	test.StrContains(t, contents, "ServerAddr some-host.com")
	test.StrContains(t, contents, "ListenAddr :8888/https :8889/http")
	test.StrContains(t, contents, "DefaultID some-id")
	test.StrContains(t, contents, "Key c29tZSBzYWx0:MTYgYnl0ZXMgZXhhY3RseQ==")
	test.StrContains(t, contents, "CertFile some cert file")
	test.StrContains(t, contents, "KeyFile some key file")
	test.StrContains(t, contents, "ClipboardName Phil's Clipboard")
	test.StrContains(t, contents, "ClipboardDir /tmp/clipboarddir")
	test.StrContains(t, contents, "ClipboardCountLimit 1234")
	test.StrContains(t, contents, "ClipboardSizeLimit 9876")
	test.StrContains(t, contents, "FileSizeLimit 777")
	test.StrContains(t, contents, "FileExpireAfter 1h 7h 0")
	test.StrContains(t, contents, "FileModesAllowed ro rw")
}

func TestConfig_WriteFileNoneOfTheThings(t *testing.T) {
	config := New()

	filename := filepath.Join(t.TempDir(), "some.conf")
	if err := config.WriteFile(filename); err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(b)
	test.StrContains(t, contents, "# ServerAddr")
	test.StrContains(t, contents, "# ListenAddr :2586")
	test.StrContains(t, contents, "# DefaultID default")
	test.StrContains(t, contents, "# Key")
	test.StrContains(t, contents, "# CertFile")
	test.StrContains(t, contents, "# KeyFile")
	test.StrContains(t, contents, "# ClipboardName pcopy")
	test.StrContains(t, contents, "# ClipboardDir /var/cache/pcopy")
	test.StrContains(t, contents, "# ClipboardCountLimit")
	test.StrContains(t, contents, "# ClipboardSizeLimit")
	test.StrContains(t, contents, "# FileSizeLimit")
	test.StrContains(t, contents, "# FileExpireAfter 7d")
	test.StrContains(t, contents, "# FileModesAllowed rw ro")
}

func TestConfig_LoadConfigFileExpireAfterNoValue(t *testing.T) {
	config, err := loadConfig(strings.NewReader(``))
	if err != nil {
		t.Fatal(err)
	}
	test.DurationEquals(t, 7*24*time.Hour, config.FileExpireAfterDefault)
	test.DurationEquals(t, 7*24*time.Hour, config.FileExpireAfterNonTextMax)
	test.DurationEquals(t, 7*24*time.Hour, config.FileExpireAfterTextMax)
}

func TestConfig_LoadConfigFileExpireAfterOneValue(t *testing.T) {
	config, err := loadConfig(strings.NewReader(`FileExpireAfter 1y`))
	if err != nil {
		t.Fatal(err)
	}
	test.DurationEquals(t, 365*24*time.Hour, config.FileExpireAfterDefault)
	test.DurationEquals(t, 365*24*time.Hour, config.FileExpireAfterNonTextMax)
	test.DurationEquals(t, 365*24*time.Hour, config.FileExpireAfterTextMax)
}

func TestConfig_LoadConfigFileExpireAfterTwoValues(t *testing.T) {
	config, err := loadConfig(strings.NewReader(`FileExpireAfter 6d 10d`))
	if err != nil {
		t.Fatal(err)
	}
	test.DurationEquals(t, 6*24*time.Hour, config.FileExpireAfterDefault)
	test.DurationEquals(t, 10*24*time.Hour, config.FileExpireAfterNonTextMax)
	test.DurationEquals(t, 10*24*time.Hour, config.FileExpireAfterTextMax)
}

func TestConfig_LoadConfigFileExpireAfterThreeValues(t *testing.T) {
	config, err := loadConfig(strings.NewReader(`FileExpireAfter 6d 10d 1w`))
	if err != nil {
		t.Fatal(err)
	}
	test.DurationEquals(t, 6*24*time.Hour, config.FileExpireAfterDefault)
	test.DurationEquals(t, 10*24*time.Hour, config.FileExpireAfterNonTextMax)
	test.DurationEquals(t, 7*24*time.Hour, config.FileExpireAfterTextMax)
}

func TestConfig_LoadConfigFileExpireAfterThreeValuesInfiniteText(t *testing.T) {
	config, err := loadConfig(strings.NewReader(`FileExpireAfter 6d 10d 0`))
	if err != nil {
		t.Fatal(err)
	}
	test.DurationEquals(t, 6*24*time.Hour, config.FileExpireAfterDefault)
	test.DurationEquals(t, 10*24*time.Hour, config.FileExpireAfterNonTextMax)
	test.DurationEquals(t, 0, config.FileExpireAfterTextMax)
}

func TestConfig_LoadConfigFromFileFailedDueToMissingCert(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := "CertFile some.crt"
	ioutil.WriteFile(filename, []byte(contents), 0700)

	_, err := LoadFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to missing cert, got none")
	}
}

func TestConfig_LoadConfigFromFileFailedDueToMissingKey(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := "KeyFile some.key"
	ioutil.WriteFile(filename, []byte(contents), 0700)

	_, err := LoadFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to missing key, got none")
	}
}

func TestConfig_LoadConfigFromFileFailedDueToInvalidClipboardSizeLimit(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := "ClipboardSizeLimit invalid-value"
	ioutil.WriteFile(filename, []byte(contents), 0700)

	_, err := LoadFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to invalid clipboard size limit, got none")
	}
}

func TestConfig_LoadConfigFromFileFailedDueToInvalidClipboardCountLimit(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := "ClipboardCountLimit invalid-value"
	ioutil.WriteFile(filename, []byte(contents), 0700)

	_, err := LoadFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to invalid clipboard count limit, got none")
	}
}

func TestConfig_LoadConfigFromFileFailedDueToInvalidFileMode1(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := "FileModesAllowed this is an invalid number"
	ioutil.WriteFile(filename, []byte(contents), 0700)

	_, err := LoadFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to invalid file modes, got none")
	}
}

func TestConfig_LoadConfigFromFileFailedDueToInvalidFileMode2(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := "FileModesAllowed rw ro123"
	ioutil.WriteFile(filename, []byte(contents), 0700)

	_, err := LoadFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to invalid file modes, got none")
	}
}

func TestConfigStore_FileFromName(t *testing.T) {
	dir := t.TempDir()
	store := newStoreWithDir(dir)
	file := store.FileFromName("work")
	test.StrEquals(t, dir+"/work.conf", file)
}

func TestConfigStore_All(t *testing.T) {
	dir := t.TempDir()
	f1, _ := os.Create(dir + "/work.conf")
	f1.Close()
	f2, _ := os.Create(dir + "/default.conf")
	f2.Close()
	store := newStoreWithDir(dir)
	configs := store.All()
	if len(configs) != 2 {
		t.Fatalf("expected two configs, got %d", len(configs))
	}
	_, ok1 := configs[dir+"/work.conf"]
	if !ok1 {
		t.Fatalf("expected 'work' entry, but didn't have one")
	}
	_, ok2 := configs[dir+"/default.conf"]
	if !ok2 {
		t.Fatalf("expected 'default' entry, but didn't have one")
	}
}

func TestExtractClipboard(t *testing.T) {
	test.StrEquals(t, "myclip", ExtractClipboard("/etc/pcopy/myclip.conf"))
}

func TestDefaultCertFile_MustNotExist(t *testing.T) {
	test.StrEquals(t, "/etc/pcopy/myclip.crt", DefaultCertFile("/etc/pcopy/myclip.conf", false))
}

func TestDefaultCertFile_MustExistSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "myclip.conf")
	expectedCertFile := filepath.Join(tmpDir, "myclip.crt")
	if err := ioutil.WriteFile(expectedCertFile, []byte("something"), 0700); err != nil {
		t.Fatal(err)
	}
	test.StrEquals(t, expectedCertFile, DefaultCertFile(configFile, true))
}

func TestDefaultKeyFile_MustNotExist(t *testing.T) {
	test.StrEquals(t, "/etc/pcopy/myclip.key", DefaultKeyFile("/etc/pcopy/myclip.conf", false))
}
