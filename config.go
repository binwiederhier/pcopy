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
)

const (
	DefaultPort = 1986
	DefaultCacheDir = "/var/cache/pcopy"
)

var SystemConfigDir = "/etc/pcopy"
var UserConfigDir = os.ExpandEnv("$HOME/.config/pcopy")

type Config struct {
	ListenAddr    string // TODO Combine with ServerAddr?
	KeyFile       string
	CertFile      string
	CacheDir      string

	ServerAddr    string
	Key           *Key
	MaxRequestAge int     // Max age in seconds for HMAC authorization
	MaxJoinAge    int     // Max age in seconds for join HMAC authorization
}

type Key struct {
	Bytes []byte
	Salt  []byte
}

var DefaultConfig = &Config{
	ListenAddr:    fmt.Sprintf(":%d", DefaultPort),
	KeyFile:       "",
	CertFile:      "",
	CacheDir:      DefaultCacheDir,

	ServerAddr:    "",
	Key:           nil,
	MaxRequestAge: 60,
	MaxJoinAge:    3600,
}

func FindConfigFile(alias string) string {
	userConfigFile := filepath.Join(os.ExpandEnv(UserConfigDir), alias + ".conf")
	systemConfigFile := filepath.Join(SystemConfigDir, alias + ".conf")

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
		return filepath.Join(SystemConfigDir, alias+".conf")
	} else {
		return filepath.Join(os.ExpandEnv(UserConfigDir), alias+".conf")
	}
}

func LoadConfig(file string, clipboard string) (string, *Config, error) {
	if file != "" {
		return loadConfigFromFile(file)
	} else {
		return loadConfigFromClipboardIfExists(clipboard)
	}
}

func DefaultCertFile(configFile string) string {
	certFile := strings.TrimSuffix(configFile, ".conf") + ".crt"
	if _, err := os.Stat(certFile); err != nil {
		return ""
	}
	return certFile
}

func DefaultKeyFile(configFile string) string {
	keyFile := strings.TrimSuffix(configFile, ".conf") + ".key"
	if _, err := os.Stat(keyFile); err != nil {
		return ""
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

	cacheDir, ok := raw["CacheDir"]
	if ok {
		config.CacheDir = os.ExpandEnv(cacheDir)
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

