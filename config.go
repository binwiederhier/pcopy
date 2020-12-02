package pcopy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	systemConfigDir = "/etc/pcopy"
	userConfigDir = "$HOME/.config/pcopy"
)

type Config struct {
	ListenAddr    string // TODO Combine with ServerAddr?
	KeyFile       string
	CertFile      string
	CacheDir      string

	ServerAddr    string
	Key           []byte
	Salt          []byte
	MaxRequestAge int     // Max age in seconds for HMAC authorization
}

var DefaultConfig = &Config{
	ListenAddr:    ":1986",
	KeyFile:       "",
	CertFile:      "",
	CacheDir:      "/var/cache/pcopy",

	ServerAddr:    "",
	Key:           nil,
	Salt:          nil,
	MaxRequestAge: 60,
}

func FindConfigFile(alias string) string {
	userConfigFile := filepath.Join(os.ExpandEnv(userConfigDir), alias + ".conf")
	systemConfigFile := filepath.Join(systemConfigDir, alias + ".conf")

	if _, err := os.Stat(userConfigFile); err == nil {
		return userConfigFile
	} else if _, err := os.Stat(systemConfigFile); err == nil {
		return systemConfigFile
	}

	return ""
}

func GetConfigFileForAlias(alias string) string {
	u, _ := user.Current()
	if u.Uid == "0" {
		return filepath.Join(systemConfigDir, alias+".conf")
	} else {
		return filepath.Join(os.ExpandEnv(userConfigDir), alias+".conf")
	}
}

func LoadConfig(file string, alias string) (string, *Config, error) {
	if file != "" {
		return loadConfigFromFile(file)
	} else {
		return loadConfigFromAliasIfExists(alias)
	}
}

func loadConfigFromAliasIfExists(alias string) (string, *Config, error) {
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
		re := regexp.MustCompile(`^([^:]+):(.+)$`)
		matches := re.FindStringSubmatch(key)
		if matches == nil {
			return "", nil, errors.New("invalid config value for 'Key'")
		}
		rawSalt, err := base64.StdEncoding.DecodeString(matches[1])
		if err != nil {
			return "", nil, errors.New("invalid config value for 'Key', cannot decode salt")
		}
		rawKey, err := base64.StdEncoding.DecodeString(matches[2])
		if err != nil {
			return "", nil, errors.New("invalid config value for 'Key', cannot decode key")
		}
		config.Key = rawKey
		config.Salt = rawSalt
	}

	maxRequestAge, ok := raw["MaxRequestAge"]
	if ok {
		config.MaxRequestAge, err = strconv.Atoi(maxRequestAge)
		if err != nil {
			return "", nil, errors.New("invalid config value for 'MaxRequestAge', must be integer")
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

