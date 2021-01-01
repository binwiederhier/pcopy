package pcopy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"
)

var templateFnMap = template.FuncMap{
	"encodeKey":        EncodeKey,
	"expandServerAddr": ExpandServerAddr,
	"encodeBase64":     base64.StdEncoding.EncodeToString,
}

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


// GenerateURL generates a URL for the given path. If the clipboard is password-protected, an auth parameter is
// added and the URL will only be valid for the given TTL.
func GenerateURL(config *Config, path string, ttl time.Duration) (string, error) {
	url := fmt.Sprintf("https://%s%s", config.ServerAddr, path)
	if config.Key != nil {
		auth, err := GenerateAuthHMAC(config.Key.Bytes, http.MethodGet, path, ttl)
		if err != nil {
			return "", err
		}
		url = fmt.Sprintf("%s?%s=%s", url, authOverrideParam, base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	return url, nil
}

// GenerateClipURL generates a URL for the clipboard entry with the given ID. If the clipboard is password-protected,
// an auth parameter is added and the URL will only be valid for the given TTL.
func GenerateClipURL(config *Config, id string, ttl time.Duration) (string, error) {
	path := fmt.Sprintf(clipboardPathFormat, id)
	return GenerateURL(config, path, ttl)
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
