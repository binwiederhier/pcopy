package pcopy

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRawConfig_WithCommentSuccess(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`WebUI true
# WebUI false`))
	if err != nil {
		t.Fatal(err)
	}
	if config["WebUI"] != "true" {
		t.Fatalf("expected %s, got %s", "true", config["WebUI"])
	}
}

func TestLoadRawConfig_OverrideSuccess(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`WebUI true
WebUI false`))
	if err != nil {
		t.Fatal(err)
	}
	if config["WebUI"] != "false" {
		t.Fatalf("expected %s, got %s", "false", config["WebUI"])
	}
}

func TestLoadRawConfig_TrimTrailingSpaceSuccess(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`WebUI "true"    `))
	if err != nil {
		t.Fatal(err)
	}
	if config["WebUI"] != `"true"` {
		t.Fatalf("expected %s, got %s", "", config["WebUI"])
	}
}

func TestLoadRawConfig_EmptyValue1Success(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`WebUI`))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := config["WebUI"]; !ok || v != "" {
		t.Fatalf("expected %s, got %s (ok: %t)", "", config["WebUI"], ok)
	}
}

func TestLoadRawConfig_EmptyValue2Success(t *testing.T) {
	config, err := loadRawConfig(strings.NewReader(`WebUI   `)) // Trailing spaces on empty value
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := config["WebUI"]; !ok || v != "" {
		t.Fatalf("expected %s, got %s (ok: %t)", "", config["WebUI"], ok)
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
	if !config.WebUI {
		t.Fatalf("expected %t, got %t", true, config.WebUI)
	}
}

func TestParseDuration_ZeroSuccess(t *testing.T) {
	d, err := parseDuration("0")
	if err != nil {
		t.Fatal(err)
	}
	if d != 0 {
		t.Fatalf("expected %d, got %d", 0, d)
	}
}

func TestParseDuration_WithDaysSuccess(t *testing.T) {
	d, err := parseDuration("10d")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10*24*time.Hour {
		t.Fatalf("expected %d, got %d", 10*24*time.Hour, d)
	}
}

func TestParseDuration_WithoutDaysSuccess(t *testing.T) {
	d, err := parseDuration("10h5m")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10*time.Hour+5*time.Minute {
		t.Fatalf("expected %d, got %d", 10*time.Hour+5*time.Minute, d)
	}
}

func TestParseDuration_WithDaysAndHoursFailure(t *testing.T) {
	_, err := parseDuration("10d1h") // not supported
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestExpandServerAddr_Expand(t *testing.T) {
	actual := ExpandServerAddr("myhost")
	expected := "myhost:2586"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestExpandServerAddr_NoExpand(t *testing.T) {
	actual := ExpandServerAddr("myhost:1234")
	expected := "myhost:1234"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestCollapseServerAddr_Collapse(t *testing.T) {
	actual := CollapseServerAddr("myhost:2586")
	expected := "myhost"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestCollapseServerAddr_NoCollapse(t *testing.T) {
	actual := CollapseServerAddr("myhost:1234")
	expected := "myhost:1234"
	if actual != expected {
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

func TestConfig_GenerateURLUnprotected(t *testing.T) {
	config := newConfig()
	config.ServerAddr = "some-host.com"

	url, err := config.GenerateURL("/some-path", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "https://some-host.com:2586/some-path", url)
}

func TestConfig_GenerateURLProtected(t *testing.T) {
	config := newConfig()
	config.ServerAddr = "some-host.com"
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}

	url, err := config.GenerateURL("/some-path", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "https://some-host.com:2586/some-path?a=SE1BQyA") {
		t.Fatalf("expected URL mismatched, got %s", url)
	}
	// TODO This should actually validate the HMAC, but the authorize() method is in server.go
}

func TestConfig_GenerateClipURLUnprotected(t *testing.T) {
	config := newConfig()
	config.ServerAddr = "some-host.com"

	url, err := config.GenerateClipURL("some-id", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "https://some-host.com:2586/some-id", url)
}

func TestConfig_WriteFileAllTheThings(t *testing.T) {
	config := newConfig()
	config.ServerAddr = "some-host.com"
	config.ListenAddr = ":8888"
	config.Key = &Key{Salt: []byte("some salt"), Bytes: []byte("16 bytes exactly")}
	config.CertFile = "some cert file"
	config.KeyFile = "some key file"
	config.ClipboardDir = "/tmp/clipboarddir"
	config.ClipboardCountLimit = 1234
	config.ClipboardSizeLimit = 9876
	config.FileSizeLimit = 777
	config.FileExpireAfter = time.Hour
	config.WebUI = false

	filename := filepath.Join(t.TempDir(), "some.conf")
	if err := config.WriteFile(filename); err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(b)
	assertStrContains(t, contents, "ServerAddr some-host.com")
	assertStrContains(t, contents, "ListenAddr :8888")
	assertStrContains(t, contents, "Key c29tZSBzYWx0:MTYgYnl0ZXMgZXhhY3RseQ==")
	assertStrContains(t, contents, "CertFile some cert file")
	assertStrContains(t, contents, "KeyFile some key file")
	assertStrContains(t, contents, "ClipboardDir /tmp/clipboarddir")
	assertStrContains(t, contents, "ClipboardCountLimit 1234")
	assertStrContains(t, contents, "ClipboardSizeLimit 9876")
	assertStrContains(t, contents, "FileSizeLimit 777")
	assertStrContains(t, contents, "FileExpireAfter 1h")
	assertStrContains(t, contents, "WebUI false")
}

func TestConfig_WriteFileNoneOfTheThings(t *testing.T) {
	config := newConfig()

	filename := filepath.Join(t.TempDir(), "some.conf")
	if err := config.WriteFile(filename); err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(b)
	assertStrContains(t, contents, "# ServerAddr")
	assertStrContains(t, contents, "ListenAddr :2586")
	assertStrContains(t, contents, "# Key")
	assertStrContains(t, contents, "# CertFile")
	assertStrContains(t, contents, "# KeyFile")
	assertStrContains(t, contents, "ClipboardDir /var/cache/pcopy")
	assertStrContains(t, contents, "# ClipboardCountLimit")
	assertStrContains(t, contents, "# ClipboardSizeLimit")
	assertStrContains(t, contents, "# FileSizeLimit")
	assertStrContains(t, contents, "FileExpireAfter 7d")
	assertStrContains(t, contents, "# WebUI")
}

func TestConfig_LoadConfigFromFileFailedDueToMissingCert(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "some.conf")
	contents := `ListenAddr :1234
CertFile some.crt
`
	if err := ioutil.WriteFile(filename, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfigFromFile(filename)
	if err == nil {
		t.Fatalf("expected error due to missing cert, got none")
	}
}

func TestParseSize_10GSuccess(t *testing.T) {
	s, err := parseSize("10G")
	if err != nil {
		t.Fatal(err)
	}
	assertInt64Equals(t, 10*1024*1024*1024, s)
}

func TestParseSize_10MUpperCaseSuccess(t *testing.T) {
	s, err := parseSize("10M")
	if err != nil {
		t.Fatal(err)
	}
	assertInt64Equals(t, 10*1024*1024, s)
}

func TestParseSize_10kLowerCaseSuccess(t *testing.T) {
	s, err := parseSize("10k")
	if err != nil {
		t.Fatal(err)
	}
	assertInt64Equals(t, 10*1024, s)
}

func TestParseSize_FailureInvalid(t *testing.T) {
	_, err := parseSize("not a size")
	if err == nil {
		t.Fatalf("expected error, but got none")
	}
}

func TestExtractClipboard(t *testing.T) {
	assertStrEquals(t, "myclip", ExtractClipboard("/etc/pcopy/myclip.conf"))
}

func TestDefaultCertFile_MustNotExist(t *testing.T) {
	assertStrEquals(t, "/etc/pcopy/myclip.crt", DefaultCertFile("/etc/pcopy/myclip.conf", false))
}

func TestDefaultCertFile_MustExistSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "myclip.conf")
	expectedCertFile := filepath.Join(tmpDir, "myclip.crt")
	if err := ioutil.WriteFile(expectedCertFile, []byte("something"), 0700); err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, expectedCertFile, DefaultCertFile(configFile, true))
}

func TestDefaultKeyFile_MustNotExist(t *testing.T) {
	assertStrEquals(t, "/etc/pcopy/myclip.key", DefaultKeyFile("/etc/pcopy/myclip.conf", false))
}
