package pcopy

import (
	"bufio"
	"os"
	"regexp"
)

var DefaultConfig = &Config{
	ListenAddr: ":1986",
	CacheDir: "",
	ServerUrl: "",
	Key: "",
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

	cacheDir, ok := raw["CacheDir"]
	if ok {
		config.CacheDir = os.ExpandEnv(cacheDir)
	}

	serverUrl, ok := raw["ServerUrl"]
	if ok {
		config.ServerUrl = serverUrl
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

