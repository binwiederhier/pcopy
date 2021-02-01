package config

import (
	"io/ioutil"
	"path/filepath"
	"strings"
)

// Store represents the config folder
type Store struct {
	dir string
}

// NewStore creates a new config store using the user-specific config dir
func NewStore() *Store {
	return newStoreWithDir(getConfigDir())
}

// newStoreWithDir creates a config store using the given directory as root
func newStoreWithDir(dir string) *Store {
	return &Store{
		dir: dir,
	}
}

// FileFromName returns the config file path for the given clipboard name.
func (c *Store) FileFromName(clipboard string) string {
	return filepath.Join(c.dir, clipboard+suffixConf)
}

// All reads the config folder and returns a map of config files and their Config structs
func (c *Store) All() map[string]*Config {
	configs := make(map[string]*Config)
	files, err := ioutil.ReadDir(c.dir)
	if err != nil {
		return configs
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), suffixConf) {
			filename := filepath.Join(c.dir, f.Name())
			config, err := LoadFromFile(filename)
			if err == nil {
				configs[filename] = config
			}
		}
	}
	return configs
}
