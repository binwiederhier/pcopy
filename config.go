package pcopy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"os"
	"regexp"
)

type Config struct {
	ListenAddr string
	KeyFile    string
	CertFile   string
	CacheDir   string

	ServerAddr string
	Key        []byte
	Salt       []byte
}

var DefaultConfig = &Config{
	ListenAddr: ":1986",
	KeyFile:    "",
	CertFile:   "",
	CacheDir:   "",
	ServerAddr: "",
	Key:        nil,
	Salt:       nil,
}

func LoadConfig(filename string) (*Config, error) {
	raw, err := loadRawConfig(filename)
	if err != nil {
		return nil, err
	}

	config := DefaultConfig

	listenAddr, ok := raw["ListenAddr"]
	if ok {
		config.ListenAddr = listenAddr
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
			return nil, errors.New("invalid config value for 'Key'")
		}
		rawSalt, err := base64.StdEncoding.DecodeString(matches[1])
		if err != nil {
			return nil, errors.New("invalid config value for 'Key', cannot decode salt")
		}
		rawKey, err := base64.StdEncoding.DecodeString(matches[2])
		if err != nil {
			return nil, errors.New("invalid config value for 'Key', cannot decode key")
		}
		config.Key = rawKey
		config.Salt = rawSalt
	}

	return config, nil
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
				rawconfig[parts[1]] = parts[2]
			}
		}
	}

	return rawconfig, nil
}

