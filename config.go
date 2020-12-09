package pcopy

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"
)

const (
	DefaultPort             = 1986
	DefaultServerConfigFile = "/etc/pcopy/server.conf"
	DefaultClipboardDir     = "/var/cache/pcopy"
	DefaultClipboard        = "default"
	DefaultFile             = "default"
	DefaultMaxJoinAge       = time.Hour
	DefaultExpireAfter      = time.Hour * 24 * 7

	systemConfigDir = "/etc/pcopy"
	userConfigDir   = "~/.config/pcopy"
)

type Config struct {
	ListenAddr   string
	ServerAddr   string
	KeyFile      string
	CertFile     string
	Key          *Key
	ClipboardDir string
	MaxJoinAge   time.Duration     // Max age in seconds for join HMAC authorization to time out
	ExpireAfter  time.Duration
}

type Key struct {
	Bytes []byte
	Salt  []byte
}

func newConfig() *Config {
	return &Config{
		ListenAddr:   fmt.Sprintf(":%d", DefaultPort),
		ServerAddr:   "",
		KeyFile:      "",
		CertFile:     "",
		Key:          nil,
		ClipboardDir: DefaultClipboardDir,
		MaxJoinAge:   DefaultMaxJoinAge,
		ExpireAfter:  DefaultExpireAfter,
	}
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

func FindNewConfigFile(clipboard string) (string, string) {
	// Try the given clipboard first
	configFile := FindConfigFile(clipboard)
	if configFile == "" {
		return clipboard, GetConfigFileForClipboard(clipboard)
	}

	// If that is taken, try single letter clipboard
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range alphabet {
		clipboard = string(c)
		configFile = FindConfigFile(clipboard)
		if configFile == "" {
			return clipboard, GetConfigFileForClipboard(clipboard)
		}
	}

	// If all of those are taken (really?), just count up
	for i := 1 ;; i++ {
		clipboard = fmt.Sprintf("a%d", i)
		configFile = FindConfigFile(clipboard)
		if configFile == "" {
			return clipboard, GetConfigFileForClipboard(clipboard)
		}
	}
}

func GetConfigFileForClipboard(clipboard string) string {
	u, _ := user.Current()
	if u.Uid == "0" {
		return filepath.Join(systemConfigDir, clipboard+".conf")
	} else {
		return filepath.Join(ExpandHome(userConfigDir), clipboard+".conf")
	}
}

func ListConfigs() map[string]*Config {
	configs := make(map[string]*Config, 0)
	dirs := []string {
		systemConfigDir,
		ExpandHome(userConfigDir),
	}
	for _, dir := range dirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") {
				filename := filepath.Join(dir, f.Name())
				_, config, err := loadConfigFromFile(filename)
				if err == nil {
					configs[filename] = config
				}
			}
		}
	}
	return configs
}

func ExtractClipboard(filename string) string {
	return strings.TrimSuffix(filepath.Base(filename), ".conf")
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
		return "", newConfig(), nil
	}
}

func loadConfigFromFile(filename string) (string, *Config, error) {
	config := newConfig()
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

	maxJoinAge, ok := raw["MaxJoinAge"]
	if ok {
		config.MaxJoinAge, err = time.ParseDuration(maxJoinAge)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'MaxJoinAge': %w", err)
		}
	}

	expireAfter, ok := raw["ExpireAfter"]
	if ok {
		config.ExpireAfter, err = time.ParseDuration(expireAfter)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'ExpireAfter': %w", err)
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

# Duration after which clipboard contents will be deleted unless they are updated before. 
# To disable, set to 0.
#
# This is a server-only option (pcopy serve). It has no effect for client commands.
#
# Format:  <number>(hms)
# Default: 7d  
#
{{if .ExpireAfter}}ExpireAfter {{.ExpireAfter}}{{else}}# ExpireAfter 7d{{end}}

# Duration for which invitation/join requests are valid. This defines how long the command generated
# by 'pcopy invite' is valid for. To disable, set to 0.
#
# This is a server-only option (pcopy serve). It has no effect for client commands.
#
# Format:  <number>(hms)
# Default: 1h
#
{{if .MaxJoinAge}}MaxJoinAge {{.MaxJoinAge}}{{else}}# MaxJoinAge 1h{{end}}

`))