package pcopy

import (
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
	if d != 10 * 24 * time.Hour {
		t.Fatalf("expected %d, got %d", 10 * 24 * time.Hour, d)
	}
}

func TestParseDuration_WithoutDaysSuccess(t *testing.T) {
	d, err := parseDuration("10h5m")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10 * time.Hour + 5 * time.Minute {
		t.Fatalf("expected %d, got %d", 10 * time.Hour + 5 * time.Minute, d)
	}
}

func TestParseDuration_WithDaysAndHoursFailure(t *testing.T) {
	_, err := parseDuration("10d1h") // not supported
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}
