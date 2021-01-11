package pcopy

import (
	"bufio"
	_ "embed" // Required for go:embed instructions
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const (
	// DefaultPort defines the default port. Server addresses without port will be expanded to include it.
	DefaultPort = 2586

	// DefaultServerConfigFile defines the default config file at which "pcopy serve" will look for the config.
	// This is a server-only setting.
	DefaultServerConfigFile = "/etc/pcopy/server.conf"

	// DefaultClipboardDir defines the default location to store the clipboard contents at. This setting is only
	// relevant for the server.
	DefaultClipboardDir = "/var/cache/pcopy"

	// DefaultClipboard defines the default clipboard name if it's not overridden by the user. This is primarily
	// used to find the config file location. This setting is only relevant for the client.
	DefaultClipboard = "default"

	// DefaultID is the default file name if none is passed by the user.
	DefaultID = "default"

	// DefaultClipboardSizeLimit is the total size in bytes that the server will allow to be written to the
	// clipboard directory. This setting is only relevant for the server.
	DefaultClipboardSizeLimit = 0

	// DefaultClipboardCountLimit is the total number of files that the server will allow in the clipboard directory.
	// This setting is only relevant for the server.
	DefaultClipboardCountLimit = 0

	// DefaultFileSizeLimit is the size in bytes that each individual clipboard file is allowed to have. The server
	// will reject files larger than that.
	DefaultFileSizeLimit = 0

	// DefaultFileExpireAfter is the duration after which the server will delete a clipboard file.
	DefaultFileExpireAfter = time.Hour * 24 * 7

	systemConfigDir = "/etc/pcopy"
	userConfigDir   = "~/.config/pcopy"
	suffixConf      = ".conf"
	suffixKey       = ".key"
	suffixCert      = ".crt"
)

var (
	// SystemdUnit contains the systemd unit file content.
	//go:embed "init/pcopy.service"
	SystemdUnit string

	//go:embed "configs/pcopy.conf.tmpl"
	configTemplateSource string
	configTemplate       = template.Must(template.New("config").Funcs(templateFnMap).Parse(configTemplateSource))

	sizeStrRegex             = regexp.MustCompile(`(?i)^(\d+)([gmkb])?$`)
	durationStrDaysOnlyRegex = regexp.MustCompile(`(?i)^(\d+)d$`)
)

// Config is the configuration struct used to configure the client and the server. Some settings only apply to
// the client, others only to the server. Some apply to both. Many (but not all) of these settings can be set either
// via the config file, or via command line parameters.
type Config struct {
	ListenAddr          string
	ServerAddr          string
	Key                 *Key
	KeyDerivIter        int
	KeyLenBytes         int
	KeyFile             string
	CertFile            string
	ClipboardDir        string
	ClipboardSizeLimit  int64
	ClipboardCountLimit int
	FileSizeLimit       int64
	FileExpireAfter     time.Duration
	ProgressFunc        ProgressFunc
	WebUI               bool
}

// ProgressFunc is callback that is called during copy/paste operations to indicate progress to the user.
type ProgressFunc func(processed int64, total int64, done bool)

// Key defines the symmetric key that is derived from the user password. It consists of the raw key bytes
// and the randomly generated salt.
type Key struct {
	Bytes []byte
	Salt  []byte
}

func newConfig() *Config {
	return &Config{
		ListenAddr:          fmt.Sprintf(":%d", DefaultPort),
		ServerAddr:          "",
		Key:                 nil,
		KeyDerivIter:        keyDerivIter,
		KeyLenBytes:         keyLenBytes,
		KeyFile:             "",
		CertFile:            "",
		ClipboardDir:        DefaultClipboardDir,
		ClipboardSizeLimit:  DefaultClipboardSizeLimit,
		ClipboardCountLimit: DefaultClipboardCountLimit,
		FileSizeLimit:       DefaultFileSizeLimit,
		FileExpireAfter:     DefaultFileExpireAfter,
		ProgressFunc:        nil,
		WebUI:               true,
	}
}

// WriteFile writes the configuration to a file.
func (c *Config) WriteFile(filename string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0744); err != nil {
		return err
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := configTemplate.Execute(f, c); err != nil {
		return err
	}

	return nil
}

// GenerateURL generates a URL for the given path. If the clipboard is password-protected, an auth parameter is
// added and the URL will only be valid for the given TTL.
func (c *Config) GenerateURL(path string, ttl time.Duration) (string, error) {
	url := fmt.Sprintf("https://%s%s", ExpandServerAddr(c.ServerAddr), path)
	if c.Key != nil {
		auth, err := GenerateAuthHMAC(c.Key.Bytes, http.MethodGet, path, ttl)
		if err != nil {
			return "", err
		}
		url = fmt.Sprintf("%s?%s=%s", url, authOverrideParam, base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	return url, nil
}

// GenerateClipURL generates a URL for the clipboard entry with the given ID. If the clipboard is password-protected,
// an auth parameter is added and the URL will only be valid for the given TTL.
func (c *Config) GenerateClipURL(id string, ttl time.Duration) (string, error) {
	path := fmt.Sprintf(clipboardPathFormat, id)
	return c.GenerateURL(path, ttl)
}

// FindConfigFile returns the path to the config file for the clipboard with the given name.
// This looks in both the system and the user config directory.
func FindConfigFile(clipboard string) string {
	userConfigFile := filepath.Join(ExpandHome(userConfigDir), clipboard+suffixConf)
	systemConfigFile := filepath.Join(systemConfigDir, clipboard+suffixConf)

	if _, err := os.Stat(userConfigFile); err == nil {
		return userConfigFile
	} else if _, err := os.Stat(systemConfigFile); err == nil {
		return systemConfigFile
	}

	return ""
}

// FindNewConfigFile finds a new config file for the given clipboard name, and returns both clipboard name
// and the config file path. If the config file with the clipboard name already exists, a new clipboard name is
// picked.
func FindNewConfigFile(clipboard string) (string, string) {
	// Try the given clipboard first
	configFile := FindConfigFile(clipboard)
	if configFile == "" {
		return clipboard, GetConfigFile(clipboard)
	}

	// If that is taken, try single letter clipboard
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	for _, c := range alphabet {
		clipboard = string(c)
		configFile = FindConfigFile(clipboard)
		if configFile == "" {
			return clipboard, GetConfigFile(clipboard)
		}
	}

	// If all of those are taken (really?), just count up
	for i := 1; ; i++ {
		clipboard = fmt.Sprintf("a%d", i)
		configFile = FindConfigFile(clipboard)
		if configFile == "" {
			return clipboard, GetConfigFile(clipboard)
		}
	}
}

// GetConfigFile returns the config file path for the given clipboard name.
func GetConfigFile(clipboard string) string {
	u, _ := user.Current()
	if u.Uid == "0" {
		return filepath.Join(systemConfigDir, clipboard+suffixConf)
	}
	return filepath.Join(ExpandHome(userConfigDir), clipboard+suffixConf)
}

// ListConfigs reads the config folder and returns a map of config files and their Config structs
func ListConfigs() map[string]*Config {
	configs := make(map[string]*Config)
	dirs := []string{
		systemConfigDir,
		ExpandHome(userConfigDir),
	}
	for _, dir := range dirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), suffixConf) {
				filename := filepath.Join(dir, f.Name())
				config, err := loadConfigFromFile(filename)
				if err == nil {
					configs[filename] = config
				}
			}
		}
	}
	return configs
}

// ExtractClipboard extracts the name of the clipboard from the config filename, e.g. the name of a clipboard with
// the config file /etc/pcopy/work.conf is "work".
func ExtractClipboard(filename string) string {
	return strings.TrimSuffix(filepath.Base(filename), suffixConf)
}

// LoadConfig is a helper to load the config file either from the given filename, or if that is empty, determine
// the filename based on the clipboard name.
func LoadConfig(filename string, clipboard string) (string, *Config, error) {
	if filename != "" {
		config, err := loadConfigFromFile(filename)
		if err != nil {
			return "", nil, err
		}
		return filename, config, err
	}
	return loadConfigFromClipboardIfExists(clipboard)
}

// ExpandServerAddr expands the server address with the default port if no port is provided,
// e.g. "myhost" will become "myhost:2586", but "myhost:1234" will remain unchanged.
func ExpandServerAddr(serverAddr string) string {
	if !strings.Contains(serverAddr, ":") {
		serverAddr = fmt.Sprintf("%s:%d", serverAddr, DefaultPort)
	}
	return serverAddr
}

// CollapseServerAddr removes the default port from the given server address if the address contains
// the default port, but leaves the address unchanged if it doesn't contain it.
func CollapseServerAddr(serverAddr string) string {
	return strings.TrimSuffix(serverAddr, fmt.Sprintf(":%d", DefaultPort))
}

// DefaultCertFile returns the default path to the certificate file, relative to the config file. If mustExist is
// true, the function returns an empty string.
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

func loadConfigFromClipboardIfExists(clipboard string) (string, *Config, error) {
	configFile := FindConfigFile(clipboard)

	if configFile != "" {
		config, err := loadConfigFromFile(configFile)
		if err != nil {
			return "", nil, err
		}
		return configFile, config, nil
	}
	return "", newConfig(), nil
}

func loadConfigFromFile(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	config, err := loadConfig(file)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func loadConfig(reader io.Reader) (*Config, error) {
	config := newConfig()
	raw, err := loadRawConfig(reader)
	if err != nil {
		return nil, err
	}

	listenAddr, ok := raw["ListenAddr"]
	if ok {
		config.ListenAddr = listenAddr
	}

	serverAddr, ok := raw["ServerAddr"]
	if ok {
		config.ServerAddr = serverAddr
	}

	key, ok := raw["Key"]
	if ok {
		config.Key, err = DecodeKey(key)
		if err != nil {
			return nil, err
		}
	}

	keyFile, ok := raw["KeyFile"]
	if ok {
		if _, err := os.Stat(keyFile); err != nil {
			return nil, err
		}
		config.KeyFile = keyFile
	}

	certFile, ok := raw["CertFile"]
	if ok {
		if _, err := os.Stat(certFile); err != nil {
			return nil, err
		}

		config.CertFile = certFile
	}

	clipboardDir, ok := raw["ClipboardDir"]
	if ok {
		config.ClipboardDir = ExpandHome(clipboardDir)
	}

	clipboardSizeLimit, ok := raw["ClipboardSizeLimit"]
	if ok {
		config.ClipboardSizeLimit, err = parseSize(clipboardSizeLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'ClipboardSizeLimit': %w", err)
		}
	}

	clipboardCountLimit, ok := raw["ClipboardCountLimit"]
	if ok {
		config.ClipboardCountLimit, err = strconv.Atoi(clipboardCountLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'ClipboardCountLimit': %w", err)
		}
	}

	fileSizeLimit, ok := raw["FileSizeLimit"]
	if ok {
		config.FileSizeLimit, err = parseSize(fileSizeLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'FileSizeLimit': %w", err)
		}
	}

	fileExpireAfter, ok := raw["FileExpireAfter"]
	if ok {
		config.FileExpireAfter, err = parseDuration(fileExpireAfter)
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'FileExpireAfter': %w", err)
		}
	}

	webUI, ok := raw["WebUI"]
	if ok {
		config.WebUI, err = strconv.ParseBool(webUI)
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'WebUI': %w", err)
		}
	}

	return config, nil
}

func parseDuration(s string) (time.Duration, error) {
	matches := durationStrDaysOnlyRegex.FindStringSubmatch(s)
	if matches == nil {
		return time.ParseDuration(s)
	}
	days, err := strconv.Atoi(matches[1])
	if err != nil {
		return -1, fmt.Errorf("cannot convert number %s", matches[1])
	}
	return time.Duration(days) * time.Hour * 24, nil
}

func parseSize(s string) (int64, error) {
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

func loadRawConfig(reader io.Reader) (map[string]string, error) {
	config := make(map[string]string)
	scanner := bufio.NewScanner(reader)

	comment := regexp.MustCompile(`^\s*#`)
	value := regexp.MustCompile(`^\s*(\S+)(?:\s+(.*)|\s*)$`)

	for scanner.Scan() {
		line := scanner.Text()

		if !comment.MatchString(line) {
			parts := value.FindStringSubmatch(line)

			if len(parts) == 3 {
				config[parts[1]] = strings.TrimSpace(parts[2])
			} else if len(parts) == 2 {
				config[parts[1]] = ""
			}
		}
	}

	return config, nil
}
