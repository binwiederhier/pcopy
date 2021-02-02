package clipboard

import (
	_ "embed" // Required for go:embed instructions
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/util"
	"io"
	"strings"
	"testing"
)

func TestClipboard_WriteFileSuccess(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)
	clip.WriteFile("howdy", io.NopCloser(strings.NewReader("howdy dude")))

	clipboardtest.Content(t, conf, "howdy", "howdy dude")
}

func TestClipboard_WriteFile_FileSizeLimitReached(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.FileSizeLimit = 10
	clip, _ := New(conf)
	if err := clip.WriteFile("sup", io.NopCloser(strings.NewReader("this is more than 10 bytes"))); err != util.ErrLimitReached {
		t.Fatalf("expected ErrLimitReached, but that didn't happen")
	}
}

func TestClipboard_WriteFile_ClipboardSizeLimitReached(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.FileSizeLimit = 10
	conf.ClipboardSizeLimit = 5
	clip, _ := New(conf)
	if err := clip.WriteFile("sup", io.NopCloser(strings.NewReader("7 bytes"))); err != util.ErrLimitReached {
		t.Fatalf("expected ErrLimitReached, but that didn't happen")
	}
}
