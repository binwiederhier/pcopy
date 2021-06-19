package server

import (
	"fmt"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
	"strings"
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
	validFor := fmt.Sprintf("valid for %s, expires %s", util.DurationToHuman(info.TTL), info.Expires.String())
	if info.TTL == 0 {
		validFor = "valid forever, does not expire"
	}
	return fmt.Sprintf(`# Direct link (%s)
%s

# Paste via pcopy (you may need a prefix)
ppaste %s

# Paste via curl
%s
`, validFor, info.URL, id, info.Curl)
}

// generateURL generates a URL for the given path. If a secret is given, it is appended as the auth param.
func generateURL(conf *config.Config, path string, secret string) (string, error) {
	server := strings.ReplaceAll(config.ExpandServerAddr(conf.ServerAddr), ":443", "")
	url := fmt.Sprintf("%s%s", server, path)
	if secret != "" {
		url = fmt.Sprintf("%s?%s=%s", url, queryParamAuth, secret)
	}
	return url, nil
}

// generateCurlCommand creates a curl command to download the given path
func generateCurlCommand(conf *config.Config, url string) (string, error) {
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
	return fmt.Sprintf("curl %s '%s'", strings.Join(args, " "), url), nil
}

// randomFileID generates a random file name
func randomFileID() string {
	return util.RandomStringWithCharset(randomFileIDLength, randomFileIDCharset)
}

// randomSecret generates a random secret
func randomSecret() string {
	return randomFileID()
}
