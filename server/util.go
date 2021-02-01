package server

import (
	"encoding/base64"
	"fmt"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
	"net/http"
	"strings"
	"time"
)

const (
	randomFileIDLength  = 10
	randomFileIDCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// FileInfoInstructions generates instruction text to download links
func FileInfoInstructions(info *File) string {
	id := info.File
	if id == config.DefaultID {
		id = ""
	}
	return fmt.Sprintf(`# Direct link (valid for %s, expires %s)
%s

# Paste via pcopy (you may need a prefix)
ppaste %s

# Paste via curl
%s
`, util.DurationToHuman(info.TTL), info.Expires.String(), info.URL, id, info.Curl)
}

// generateURL generates a URL for the given path. If the clipboard is password-protected, an auth parameter is
// added and the URL will only be valid for the given TTL.
func generateURL(conf *config.Config, path string, ttl time.Duration) (string, error) {
	server := strings.ReplaceAll(config.ExpandServerAddr(conf.ServerAddr), ":443", "")
	url := fmt.Sprintf("%s%s", server, path)
	if conf.Key != nil {
		auth, err := crypto.GenerateAuthHMAC(conf.Key.Bytes, http.MethodGet, path, ttl)
		if err != nil {
			return "", err
		}
		url = fmt.Sprintf("%s?%s=%s", url, queryParamAuth, base64.RawURLEncoding.EncodeToString([]byte(auth)))
	}
	return url, nil
}

// generateCurlCommand creates a curl command to download the given path
func generateCurlCommand(conf *config.Config, path string, ttl time.Duration) (string, error) {
	args := make([]string, 0)
	if conf.CertFile == "" {
		args = append(args, "-sSL")
	} else {
		pin, err := crypto.ReadCurlPinnedPublicKeyFromFile(conf.CertFile)
		if err != nil {
			args = append(args, "-sSLk")
		} else if pin != "" {
			args = append(args, "-sSLk", fmt.Sprintf("--pinnedpubkey %s", pin))
		} else {
			args = append(args, "-sSL")
		}
	}
	url, err := generateURL(conf, path, ttl)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("curl %s '%s'", strings.Join(args, " "), url), nil
}

// randomFileID generates a random file name
func randomFileID() string {
	return util.RandomStringWithCharset(randomFileIDLength, randomFileIDCharset)
}
