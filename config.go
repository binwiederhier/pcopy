package pcopy

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

const (
	DefaultPort = 1986
	DefaultClipboardDir = "/var/cache/pcopy"
	DefaultClipboard = "default"
	DefaultFile = "default"

	systemConfigDir = "/etc/pcopy"
	userConfigDir   = "~/.config/pcopy"
)

type Config struct {
	ListenAddr    string
	ServerAddr    string
	KeyFile       string
	CertFile      string
	Key           *Key
	ClipboardDir  string
	MaxRequestAge int     // Max age in seconds for copy/paste HMAC authorization to time out
	MaxJoinAge    int     // Max age in seconds for join HMAC authorization to time out
}

type Key struct {
	Bytes []byte
	Salt  []byte
}

var DefaultConfig = &Config{
	ListenAddr:    fmt.Sprintf(":%d", DefaultPort),
	ServerAddr:    "",
	KeyFile:       "",
	CertFile:      "",
	Key:           nil,
	ClipboardDir:  DefaultClipboardDir,
	MaxRequestAge: 60,
	MaxJoinAge:    3600,
}

func (c *Config) WriteFile(filename string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0744); err != nil {
		return err
	}

	f, err := os.OpenFile(filename, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := configTemplate.Execute(f, c); err != nil {
		return err
	}

	return nil
}

func FindConfigFile(alias string) string {
	userConfigFile := filepath.Join(ExpandHome(userConfigDir), alias + ".conf")
	systemConfigFile := filepath.Join(systemConfigDir, alias + ".conf")

	if _, err := os.Stat(userConfigFile); err == nil {
		return userConfigFile
	} else if _, err := os.Stat(systemConfigFile); err == nil {
		return systemConfigFile
	}

	return ""
}

func FindNewConfigFile(alias string) (string, string) {
	// Try the given alias first
	configFile := FindConfigFile(alias)
	if configFile == "" {
		return alias, GetConfigFileForAlias(alias)
	}

	// If that is taken, try single letter alias
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range alphabet {
		alias = string(c)
		configFile = FindConfigFile(alias)
		if configFile == "" {
			return alias, GetConfigFileForAlias(alias)
		}
	}

	// If all of those are taken (really?), just count up
	for i := 1 ;; i++ {
		alias = fmt.Sprintf("a%d", i)
		configFile = FindConfigFile(alias)
		if configFile == "" {
			return alias, GetConfigFileForAlias(alias)
		}
	}
}

func GetConfigFileForAlias(alias string) string {
	u, _ := user.Current()
	if u.Uid == "0" {
		return filepath.Join(systemConfigDir, alias+".conf")
	} else {
		return filepath.Join(ExpandHome(userConfigDir), alias+".conf")
	}
}

func LoadConfig(file string, clipboard string) (string, *Config, error) {
	if file != "" {
		return loadConfigFromFile(file)
	} else {
		return loadConfigFromClipboardIfExists(clipboard)
	}
}

func ExpandServerAddr(serverAddr string) string {
	if !strings.Contains(serverAddr, ":") {
		serverAddr = fmt.Sprintf("%s:%d", serverAddr, DefaultPort)
	}
	return serverAddr
}

func DefaultCertFile(configFile string, mustExist bool) string {
	return defaultFileWithNewExt(".crt", configFile, mustExist)
}

func DefaultKeyFile(configFile string, mustExist bool) string {
	return defaultFileWithNewExt(".key", configFile, mustExist)
}

func defaultFileWithNewExt(newExtension string, configFile string, mustExist bool) string {
	keyFile := strings.TrimSuffix(configFile, ".conf") + newExtension
	if mustExist {
		if _, err := os.Stat(keyFile); err != nil {
			return ""
		}
	}

	return keyFile
}

func loadConfigFromClipboardIfExists(alias string) (string, *Config, error) {
	configFile := FindConfigFile(alias)

	if configFile != "" {
		file, config, err := loadConfigFromFile(configFile)
		if err != nil {
			return "", nil, err
		}
		return file, config, nil
	} else {
		return "", DefaultConfig, nil
	}
}

func loadConfigFromFile(filename string) (string, *Config, error) {
	config := DefaultConfig
	raw, err := loadRawConfig(filename)
	if err != nil {
		return "", nil, err
	}

	listenAddr, ok := raw["ListenAddr"]
	if ok {
		config.ListenAddr = listenAddr
	}

	keyFile, ok := raw["KeyFile"]
	if ok {
		if _, err := os.Stat(keyFile); err != nil {
			return "", nil, err
		}
		config.KeyFile = keyFile
	}

	certFile, ok := raw["CertFile"]
	if ok {
		if _, err := os.Stat(certFile); err != nil {
			return "", nil, err
		}

		config.CertFile = certFile
	}

	clipboardDir, ok := raw["ClipboardDir"]
	if ok {
		config.ClipboardDir = ExpandHome(clipboardDir)
	}

	serverAddr, ok := raw["ServerAddr"]
	if ok {
		config.ServerAddr = serverAddr
	}

	key, ok := raw["Key"]
	if ok {
		config.Key, err = DecodeKey(key)
		if err != nil {
			return "", nil, err
		}
	}

	maxRequestAge, ok := raw["MaxRequestAge"]
	if ok {
		config.MaxRequestAge, err = strconv.Atoi(maxRequestAge)
		if err != nil {
			return "", nil, errors.New("invalid config value for 'MaxRequestAge', must be integer")
		}
	}

	maxJoinAge, ok := raw["MaxJoinAge"]
	if ok {
		config.MaxJoinAge, err = strconv.Atoi(maxJoinAge)
		if err != nil {
			return "", nil, errors.New("invalid config value for 'MaxJoinAge', must be integer")
		}
	}

	return filename, config, nil
}

func loadRawConfig(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rawconfig := make(map[string]string)
	scanner := bufio.NewScanner(file)

	comment := regexp.MustCompile(`^\s*#`)
	value := regexp.MustCompile(`^\s*(\S+)\s+(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()

		if !comment.MatchString(line) {
			parts := value.FindStringSubmatch(line)

			if len(parts) == 3 {
				rawconfig[parts[1]] = strings.TrimSpace(parts[2])
			}
		}
	}

	return rawconfig, nil
}


var templateFuncMap = template.FuncMap{"encodeKey": EncodeKey}
var configTemplate = template.Must(template.New("").Funcs(templateFuncMap).Parse(
	`# pcopy config file

# Hostname and port of the pcopy server
#
# For servers: This address is advertised to clients. It is not strictly necessary for normal copy/paste operations, 
# but required for the easy-install process via 'pcopy invite'. If PORT is not defined, the default port 1986 is used. 
# 
# Format:    HOST[:PORT]
# Default:   None
#
{{if .ServerAddr}}ServerAddr {{.ServerAddr}}{{else}}# ServerAddr{{end}}

# Address and port to use to bind the server. To bind to all addresses, you may omit the address,
# e.g. :2586.
#
# This is a server-only option (pcopy serve). It has no effect for client commands.
#
# Format:  [ADDR]:PORT
# Default: :1986
#
{{if .ListenAddr}}ListenAddr {{.ListenAddr}}{{else}}# ListenAddr :1986{{end}}

# If a key is defined, clients need to auth whenever they want copy/paste values
# to the clipboard. A key is derived from a password and can be generated using
# the 'pcopy keygen' command.
# 
# Format:  SALT:KEY (both base64 encoded)
# Default: None
#
{{if .Key}}Key {{encodeKey .Key}}{{else}}# Key{{end}}

# Path to the TLS certificate used for the HTTPS traffic. If not set, the config file path (with 
# a .crt extension) is assumed to be the path to the certificate, e.g. server.crt (if the config
# file is server.conf). 
#
# For servers: This certificate is served to clients.
# For clients: If a certificate is present, it is used as the only allowed certificate to communicate
#              with a server (cert pinning). 
#
# Format:  /some/path/to/server.crt (PEM formatted)
# Default: Config path, but with .crt extension
#
{{if .CertFile}}CertFile {{.CertFile}}{{else}}# CertFile{{end}}

# Path to the private key for the matching certificate. If not set, the config file path (with 
# a .key extension) is assumed to be the path to the private key, e.g. server.key (if the config
# file is server.conf).
#
# This is a server-only option (pcopy serve). It has no effect for client commands.
#
# Format:  /some/path/to/server.key (PEM formatted)
# Default: Config path, but with .key extension
#
{{if .KeyFile}}KeyFile {{.KeyFile}}{{else}}# KeyFile{{end}}

# Path to the directory in which the clipboard resides. If not set, this defaults to 
# the path /var/cache/pcopy.
#
# This is a server-only option (pcopy serve). It has no effect for client commands.
#
# Format:  /some/folder
# Default: /var/cache/pcopy
#
{{if .ClipboardDir}}ClipboardDir {{.ClipboardDir}}{{else}}# ClipboardDir /var/cache/pcopy{{end}}
`))