package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ExtractClipboard extracts the name of the clipboard from the config filename, e.g. the name of a clipboard with
// the config file /etc/pcopy/work.conf is "work".
func ExtractClipboard(filename string) string {
	return strings.TrimSuffix(filepath.Base(filename), suffixConf)
}

// ExpandServerAddr expands the server address with the default port if no port is provided to a full URL, including
// protocol prefix. For instance: "myhost" will become "https://myhost:2586", and "myhost:443" will become "https://myhost",
// but "http://myhost:1234" will remain unchanged.
func ExpandServerAddr(serverAddr string) string {
	if strings.HasPrefix(serverAddr, "http://") || strings.HasPrefix(serverAddr, "https://") {
		return serverAddr
	}
	if !strings.Contains(serverAddr, ":") {
		serverAddr = fmt.Sprintf("%s:%d", serverAddr, DefaultPort)
	}
	return fmt.Sprintf("https://%s", strings.ReplaceAll(serverAddr, ":443", ""))
}

// ExpandServerAddrsGuess expands the server address (similar to ExpandServerAddr), except that it will return
// two addresses if no explicit port is passed: one with the default port and one with port 443. This is to be
// able to do "pcopy join example.com" and have it work unless it's not the default or not 443.
func ExpandServerAddrsGuess(serverAddr string) []string {
	if strings.HasPrefix(serverAddr, "http://") || strings.HasPrefix(serverAddr, "https://") {
		return []string{serverAddr}
	}
	if strings.Contains(serverAddr, ":") {
		return []string{fmt.Sprintf("https://%s", serverAddr)}
	}
	return []string{
		fmt.Sprintf("https://%s", serverAddr),
		fmt.Sprintf("https://%s:%d", serverAddr, DefaultPort),
	}
}

// CollapseServerAddr removes the default port from the given server address if the address contains
// the default port, but leaves the address unchanged if it doesn't contain it.
func CollapseServerAddr(serverAddr string) string {
	if strings.HasPrefix(serverAddr, "http://") {
		return serverAddr
	}
	if strings.HasPrefix(serverAddr, "https://") {
		u, err := url.Parse(serverAddr)
		if err != nil {
			return serverAddr
		}
		if u.Port() == "" || u.Port() == "443" {
			return fmt.Sprintf("%s:443", u.Host)
		}
		return strings.TrimSuffix(u.Host, fmt.Sprintf(":%d", DefaultPort))
	}
	return strings.TrimSuffix(serverAddr, fmt.Sprintf(":%d", DefaultPort))
}

// DefaultCertFile returns the default path to the certificate file, relative to the config file. If mustExist is
// true, the function returns an empty string if the file does not exist.
func DefaultCertFile(configFile string, mustExist bool) string {
	return defaultFileWithNewExt(suffixCert, configFile, mustExist)
}

// DefaultKeyFile returns the default path to the key file, relative to the config file. If mustExist is
// true, the function returns an empty string.
func DefaultKeyFile(configFile string, mustExist bool) string {
	return defaultFileWithNewExt(suffixKey, configFile, mustExist)
}

func defaultFileWithNewExt(newExtension string, configFile string, mustExist bool) string {
	file := strings.TrimSuffix(configFile, suffixConf) + newExtension
	if mustExist {
		if _, err := os.Stat(file); err != nil {
			return ""
		}
	}
	return file
}
