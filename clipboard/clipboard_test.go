package clipboard

import (
	"bytes"
	_ "embed" // Required for go:embed instructions
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/test"
	"heckel.io/pcopy/util"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClipboard_WriteFileSuccess(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)

	meta := &File{Mode: config.FileModeReadOnly, Expires: time.Now().Add(time.Hour).Unix()}
	clip.WriteFile("howdy", meta, io.NopCloser(strings.NewReader("howdy dude")))

	clipboardtest.Content(t, conf, "howdy", "howdy dude")
}

func TestClipboard_WriteFile_FileSizeLimitReached(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.FileSizeLimit = 10
	clip, _ := New(conf)
	meta := &File{Mode: config.FileModeReadWrite, Expires: time.Now().Add(time.Hour).Unix()}
	if err := clip.WriteFile("sup", meta, io.NopCloser(strings.NewReader("this is more than 10 bytes"))); err != util.ErrLimitReached {
		t.Fatalf("expected ErrLimitReached, but that didn't happen")
	}
	file, metafile, _ := clip.getFilenames("sup")
	test.FileNotExist(t, file)
	test.FileNotExist(t, metafile)
}

func TestClipboard_WriteFile_ClipboardSizeLimitReached(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.FileSizeLimit = 10
	conf.ClipboardSizeLimit = 5
	clip, _ := New(conf)
	meta := &File{Mode: config.FileModeReadWrite, Expires: time.Now().Add(time.Hour).Unix()}
	if err := clip.WriteFile("sup", meta, io.NopCloser(strings.NewReader("7 bytes"))); err != util.ErrLimitReached {
		t.Fatalf("expected ErrLimitReached, but that didn't happen")
	}
}

func TestClipboard_WriteFile_ReadFile(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)
	meta := &File{Mode: config.FileModeReadWrite, Expires: time.Now().Add(time.Hour).Unix()}
	clip.WriteFile("sup", meta, io.NopCloser(strings.NewReader("7 bytes")))

	var buf bytes.Buffer
	clip.ReadFile("sup", &buf)
	test.StrEquals(t, "7 bytes", buf.String())
}

func TestClipboard_Stats(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)

	meta := &File{Mode: config.FileModeReadWrite, Expires: time.Now().Add(time.Hour).Unix()}
	clip.WriteFile("sup", meta, io.NopCloser(strings.NewReader("7 bytes")))
	clip.WriteFile("sup2", meta, io.NopCloser(strings.NewReader("this is a sting with 29 bytes")))

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

	meta := &File{Mode: config.FileModeReadWrite, Expires: time.Now().Add(-time.Hour).Unix()}
	clip.WriteFile("sup", meta, io.NopCloser(strings.NewReader("7 bytes")))

	stat, _ := clip.Stat("sup")
	test.StrEquals(t, "sup", stat.ID)

	clip.Expire()

	stat, _ = clip.Stat("sup")
	if stat != nil {
		t.Fatalf("expected stat to be nil, but it is not: %#v", stat)
	}
}

func TestClipboard_MakePipe(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)
	clip.MakePipe("sup")

	file, _, _ := clip.getFilenames("sup")
	stat, _ := os.Stat(file)
	test.BoolEquals(t, true, stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe)
}

func TestClipboard_ValidID(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	clip, _ := New(conf)
	test.BoolEquals(t, true, clip.isValidID("valid-id"))
	test.BoolEquals(t, true, clip.isValidID("valid.txt"))
	test.BoolEquals(t, false, clip.isValidID("robots.txt"))
	test.BoolEquals(t, false, clip.isValidID("favicon.ico"))
	test.BoolEquals(t, false, clip.isValidID(""))
	test.BoolEquals(t, false, clip.isValidID("/hi"))
	test.BoolEquals(t, false, clip.isValidID("äöüß.txt"))
	test.BoolEquals(t, false, clip.isValidID(".invalid"))
	test.BoolEquals(t, false, clip.isValidID("this-is-so-log-that-it-cannot-by-any-possible-reasoning-be-valid-so-this-is-really-rally-invalid-because-it-is-too-long"))
}
