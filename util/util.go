// Package util contains utility functions and general purpose writers/readers
package util

import (
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	random                         = rand.New(rand.NewSource(time.Now().UnixNano()))
	durationStrSecondsOnlyRegex    = regexp.MustCompile(`(?i)^(\d+)$`)
	durationStrLongPeriodOnlyRegex = regexp.MustCompile(`(?i)^(\d+)([dwy]|mo)$`)
	sizeStrRegex                   = regexp.MustCompile(`(?i)^(\d+)([gmkb])?$`)
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
	if d == 0 {
		return "0"
	}

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

// ParseDuration is a wrapper around Go's time.ParseDuration to supports days, weeks, months and years ("2y")
// and values without any unit ("1234"), which are interpreted as seconds. This is obviously inaccurate,
// but enough for the use case. In this function, the units are defined as follows:
// - day = 24 hours
// - week = 7 days
// - month = 30 days
// - year = 365 days
func ParseDuration(s string) (time.Duration, error) {
	matches := durationStrSecondsOnlyRegex.FindStringSubmatch(s)
	if matches != nil {
		seconds, err := strconv.Atoi(matches[1])
		if err != nil {
			return -1, fmt.Errorf("cannot convert number %s", matches[1])
		}
		return time.Duration(seconds) * time.Second, nil
	}
	matches = durationStrLongPeriodOnlyRegex.FindStringSubmatch(s)
	if matches != nil {
		number, err := strconv.Atoi(matches[1])
		if err != nil {
			return -1, fmt.Errorf("cannot convert number %s", matches[1])
		}
		switch unit := matches[2]; unit {
		case "d":
			return time.Duration(number) * 24 * time.Hour, nil
		case "w":
			return time.Duration(number) * 7 * 24 * time.Hour, nil
		case "mo":
			return time.Duration(number) * 30 * 24 * time.Hour, nil
		case "y":
			return time.Duration(number) * 365 * 24 * time.Hour, nil
		default:
			return -1, fmt.Errorf("unexpected unit %s", unit)
		}
	}
	return time.ParseDuration(s)
}

// ParseSize parses a size string like 2K or 2M into bytes. If no unit is found, e.g. 123, bytes is assumed.
func ParseSize(s string) (int64, error) {
	matches := sizeStrRegex.FindStringSubmatch(s)
	if matches == nil {
		return -1, fmt.Errorf("invalid size %s", s)
	}
	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return -1, fmt.Errorf("cannot convert number %s", matches[1])
	}
	switch strings.ToUpper(matches[2]) {
	case "G":
		return int64(value) * 1024 * 1024 * 1024, nil
	case "M":
		return int64(value) * 1024 * 1024, nil
	case "K":
		return int64(value) * 1024, nil
	default:
		return int64(value), nil
	}
}

// RandomStringWithCharset returns a random string with a given length, using the defined charset
func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[random.Intn(len(charset))]
	}
	return string(b)
}

// ReadPassword will read a password from STDIN. If the terminal supports it, it will not print the
// input characters to the screen. If not, it'll just read using normal readline semantics (useful for testing).
func ReadPassword(in io.Reader) ([]byte, error) {
	// If in is a file and a character device (a TTY), use term.ReadPassword
	if f, ok := in.(*os.File); ok {
		stat, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if (stat.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
			password, err := term.ReadPassword(int(f.Fd())) // This is always going to be 0
			if err != nil {
				return nil, err
			}
			return password, nil
		}
	}

	// Fallback: Manually read util \n if found, see #69 for details why this is so manual
	password := make([]byte, 0)
	buf := make([]byte, 1)
	for {
		_, err := in.Read(buf)
		if err == io.EOF || buf[0] == '\n' {
			break
		} else if err != nil {
			return nil, err
		} else if len(password) > 10240 {
			return nil, errors.New("passwords this long are not supported")
		}
		password = append(password, buf[0])
	}

	return password, nil
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
