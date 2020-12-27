package pcopy

import (
	"bufio"
	_ "embed"
	"fmt"
	"io/ioutil"
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
	DefaultPort               = 1986
	DefaultServerConfigFile   = "/etc/pcopy/server.conf"
	DefaultClipboardDir       = "/var/cache/pcopy"
	DefaultClipboard          = "default"
	DefaultId                 = "default"
	DefaultFileExpireAfter    = time.Hour * 24 * 7
	DefaultClipboardSizeLimit = 0
	DefaultFileSizeLimit      = 0
	DefaultFileCountLimit     = 0

	systemConfigDir = "/etc/pcopy"
	userConfigDir   = "~/.config/pcopy"
)

var (
	sizeStrRegex = regexp.MustCompile(`(?i)^(\d+)([gmkb])?$`)

	//go:embed "configs/pcopy.conf.tmpl"
	configTemplateSource string
	configTemplate = template.Must(template.New("config").Funcs(templateFnMap).Parse(configTemplateSource))
)

type Config struct {
	ListenAddr         string
	ServerAddr         string
	Key                *Key
	KeyDerivIter       int
	KeyLenBytes        int
	KeyFile            string
	CertFile           string
	ClipboardDir       string
	ClipboardSizeLimit int64
	FileSizeLimit      int64
	FileCountLimit     int
	FileExpireAfter    time.Duration
	ProgressFunc       ProgressFunc
	WebUI              bool
}

type Key struct {
	Bytes []byte
	Salt  []byte
}

func newConfig() *Config {
	return &Config{
		ListenAddr:         fmt.Sprintf(":%d", DefaultPort),
		ServerAddr:         "",
		Key:                nil,
		KeyDerivIter:       keyDerivIter,
		KeyLenBytes:        keyLenBytes,
		KeyFile:            "",
		CertFile:           "",
		ClipboardDir:       DefaultClipboardDir,
		ClipboardSizeLimit: DefaultClipboardSizeLimit,
		FileSizeLimit:      DefaultFileSizeLimit,
		FileCountLimit:     DefaultFileCountLimit,
		FileExpireAfter:    DefaultFileExpireAfter,
		ProgressFunc:       nil,
		WebUI:              true,
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

func CollapseServerAddr(serverAddr string) string {
	return strings.TrimSuffix(serverAddr,fmt.Sprintf(":%d", DefaultPort))
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

	clipboardSizeLimit, ok := raw["ClipboardSizeLimit"]
	if ok {
		config.ClipboardSizeLimit, err = parseSize(clipboardSizeLimit)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'ClipboardSizeLimit': %w", err)
		}
	}

	fileSizeLimit, ok := raw["FileSizeLimit"]
	if ok {
		config.FileSizeLimit, err = parseSize(fileSizeLimit)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'FileSizeLimit': %w", err)
		}
	}

	fileCountLimit, ok := raw["FileCountLimit"]
	if ok {
		config.FileCountLimit, err = strconv.Atoi(fileCountLimit)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'FileCountLimit': %w", err)
		}
	}

	fileExpireAfter, ok := raw["FileExpireAfter"]
	if ok {
		config.FileExpireAfter, err = time.ParseDuration(fileExpireAfter)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'FileExpireAfter': %w", err)
		}
	}

	webUI, ok := raw["WebUI"]
	if ok {
		config.WebUI, err = strconv.ParseBool(webUI)
		if err != nil {
			return "", nil, fmt.Errorf("invalid config value for 'WebUI': %w", err)
		}
	}

	return filename, config, nil
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
	case "G": return int64(value) * 1024 * 1024 * 1024, nil
	case "M": return int64(value) * 1024 * 1024, nil
	case "K": return int64(value) * 1024, nil
	default: return int64(value), nil
	}
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
