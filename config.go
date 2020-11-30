package pcopy

import (
	"bufio"
	"os"
	"regexp"
)

type Config struct {
	ListenAddr string
	KeyFile    string
	CertFile   string
	CacheDir   string

	ServerAddr string
	Key        string
}

var DefaultConfig = &Config{
	ListenAddr: ":1986",
	KeyFile:    "", // defaults to basename.key
	CertFile:   "", // defaults to basename.crt
	CacheDir:   "",
	ServerAddr: "",
	Key:        "",
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
		config.Key = key
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

