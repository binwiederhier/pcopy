package pcopy

import (
	"encoding/base64"
	"fmt"
	htmltemplate "html/template"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

var (
	random        = rand.New(rand.NewSource(time.Now().UnixNano()))
	templateFnMap = template.FuncMap{
		"encodeKey":        EncodeKey,
		"expandServerAddr": ExpandServerAddr,
		"encodeBase64":     base64.StdEncoding.EncodeToString,
		"bytesToHuman":     BytesToHuman,
		"durationToHuman":  DurationToHuman,
		"stringsJoin":      strings.Join,
		"htmlEscape":       htmltemplate.HTMLEscapeString,
	}
)

const (
	randomFileIDLength  = 10
	randomFileIDCharset = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// ExpandHome replaces "~" with the user's home directory
func ExpandHome(path string) string {
	return os.ExpandEnv(strings.ReplaceAll(path, "~", "$HOME"))
}

// CollapseHome shortens a path that contains a user's home directory with "~"
func CollapseHome(path string) string {
	home := os.Getenv("HOME")
	if home != "" && strings.HasPrefix(path, home) {
		return fmt.Sprintf("~%s", strings.TrimPrefix(path, home))
	}
	return path
}

// BytesToHuman converts bytes to human readable format, e.g. 10 KB or 10.8 MB
func BytesToHuman(b int64) string {
	// From: https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// DurationToHuman converts a duration to a human readable format
func DurationToHuman(d time.Duration) (str string) {
	d = d.Round(time.Second)
	days := d / time.Hour / 24
	if days > 0 {
		str += fmt.Sprintf("%dd", days)
	}
	d -= days * time.Hour * 24

	hours := d / time.Hour
	if hours > 0 {
		str += fmt.Sprintf("%dh", hours)
	}
	d -= hours * time.Hour

	minutes := d / time.Minute
	if minutes > 0 {
		str += fmt.Sprintf("%dm", minutes)
	}
	d -= minutes * time.Minute

	seconds := d / time.Second
	if seconds > 0 {
		str += fmt.Sprintf("%ds", seconds)
	}
	return
}

// FileInfoInstructions generates instruction text to download links
func FileInfoInstructions(info *FileInfo) string {
	id := info.File
	if id == DefaultID {
		id = ""
	}
	return fmt.Sprintf(`# Direct link (valid for %s, expires %s)
%s

# Paste via pcopy (you may need a prefix)
ppaste %s

# Paste via curl
%s
`, DurationToHuman(info.TTL), info.Expires.String(), info.URL, id, info.Curl)
}

// commonPrefix determines the longest common prefix across a list of paths.
// The given paths can be files or directories.
func commonPrefix(paths []string) string {
	// From: https://rosettacode.org/wiki/Find_common_directory_path#Go (GFDLv1.2)
	// Some comments have been removed for brevity.

	// Handle special cases.
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return path.Clean(paths[0])
	}

	// Note, we treat string as []byte, not []rune as is often done in Go. This is okay,
	// see link above for details.
	c := []byte(path.Clean(paths[0]))

	// We add a trailing sep to handle the case where the common prefix directory is included in the path
	// list (e.g. /home/user1, /home/user1/foo, /home/user1/bar). path.Clean will have cleaned off trailing /
	// separators with the exception of the root directory, "/" (in which case we make it "//", but this will get
	// fixed up to "/" bellow).
	sep := byte(filepath.Separator)
	c = append(c, sep)

	// Ignore the first path since it's already in c
	for _, v := range paths[1:] {
		v = path.Clean(v) + string(sep)

		if len(v) < len(c) {
			c = c[:len(v)] // Find the first non-common byte and truncate c
		}
		for i := 0; i < len(c); i++ {
			if v[i] != c[i] {
				c = c[:i]
				break
			}
		}
	}

	// Remove trailing non-separator characters and the final separator
	for i := len(c) - 1; i >= 0; i-- {
		if c[i] == sep {
			c = c[:i]
			break
		}
	}

	return string(c)
}

// relativizeFiles takes a list of files (NOT folders!), find their common prefix and relativizes them
// baed on that prefix.
func relativizeFiles(files []string) (string, []string, error) {
	// Turn all given files into absolute paths
	var err error
	abs := make([]string, len(files))
	for i, f := range files {
		abs[i], err = filepath.Abs(f)
		if err != nil {
			return "", nil, err
		}
	}

	// Handle special cases
	switch len(abs) {
	case 0:
		return "", []string{}, nil
	case 1:
		return filepath.Dir(abs[0]), []string{filepath.Base(abs[0])}, nil
	}

	// Find common path and relativize all files based on it
	base := commonPrefix(abs)
	rel := make([]string, len(abs))
	for i, f := range abs {
		rel[i] = f[len(base)+1:]
	}
	return base, rel, nil
}

func randomFileID() string {
	return randomStringWithCharset(randomFileIDLength, randomFileIDCharset)
}

func randomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[random.Intn(len(charset))]
	}
	return string(b)
}
