package clipboard

import (
	"bytes"
	_ "embed" // Required for go:embed instructions
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/test"
	"heckel.io/pcopy/util"
	"io"
	"strings"
	"testing"
	"time"
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

func TestClipboard_WriteFile_ReadFile(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)
	clip.WriteFile("sup", io.NopCloser(strings.NewReader("7 bytes")))

	var buf bytes.Buffer
	clip.ReadFile("sup", &buf)
	test.StrEquals(t, "7 bytes", buf.String())
}

func TestClipboard_Stats(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)

	clip.WriteMeta("sup", "rw", 0)
	clip.WriteFile("sup", io.NopCloser(strings.NewReader("7 bytes")))

	clip.WriteMeta("sup2", "rw", 0)
	clip.WriteFile("sup2", io.NopCloser(strings.NewReader("this is a sting with 29 bytes")))

	stats, _ := clip.Stats()
	test.Int64Equals(t, 36, stats.Size)
	test.Int64Equals(t, 2, int64(stats.Count))
}

func TestClipboard_Allow(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.ClipboardCountLimit = 10
	clip, _ := New(conf)

	for i := 0; i < 10; i++ {
		test.BoolEquals(t, true, clip.Allow())
	}
	test.BoolEquals(t, false, clip.Allow())
}

func TestClipboard_Expire(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)

	clip.WriteMeta("sup", "rw", time.Now().Add(-time.Hour).Unix())
	clip.WriteFile("sup", io.NopCloser(strings.NewReader("7 bytes")))

	stat, _ := clip.Stat("sup")
	test.StrEquals(t, "sup", stat.ID)

	clip.Expire()

	stat, _ = clip.Stat("sup")
	if stat != nil {
		t.Fatalf("expected stat to be nil, but it is not: %#v", stat)
	}
}
