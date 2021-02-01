package clipboardtest

import (
	"heckel.io/pcopy/config"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// NotExist ensures that a clipboard entry does not exist and fails t if it does
func NotExist(t *testing.T, conf *config.Config, id string) {
	filename := filepath.Join(conf.ClipboardDir, id)
	if _, err := os.Stat(filename); err == nil {
		t.Fatalf("expected file %s to not exist, but it does", filename)
	}
}

// Content ensures that a clipboard entry has the expected content and fails t if it has not
func Content(t *testing.T, conf *config.Config, id string, content string) {
	filename := filepath.Join(conf.ClipboardDir, id)
	actualContent, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualContent) != content {
		t.Fatalf("expected %s, got %s", content, actualContent)
	}
}
