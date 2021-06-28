// Package config provides an interface to configure a pcopy server and client
package config

import (
	"bufio"
	_ "embed" // Required for go:embed instructions
	"fmt"
	"golang.org/x/time/rate"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
	"io"
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

	// DefaultClipboardName defines the default name of the clipboard as it appears in the Web UI
	DefaultClipboardName = "pcopy"

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

	// DefaultFileModesAllowed is the default setting for whether files are overwritable
	DefaultFileModesAllowed = "rw ro"

	// FileModeReadWrite allows files to be overwritten
	FileModeReadWrite = "rw"

	// FileModeReadOnly ensures that files cannot be overwritten
	FileModeReadOnly = "ro"

	// EnvKey provides the ability to provide a key for certain CLI commands
	EnvKey = "PCOPY_KEY"

	// EnvConfigDir allows overriding the user-specific config dir
	EnvConfigDir = "PCOPY_CONFIG_DIR"

	systemConfigDir        = "/etc/pcopy"
	userConfigDir          = "~/.config/pcopy"
	suffixConf             = ".conf"
	suffixKey              = ".key"
	suffixCert             = ".crt"
	defaultManagerInterval = 30 * time.Second
)

var (
	// SystemdUnit contains the systemd unit file content.
	//go:embed "pcopy.service"
	SystemdUnit string

	//go:embed "config.conf.tmpl"
	configTemplateSource string
	configTemplate       = template.Must(template.New("config").Funcs(templateFnMap).Parse(configTemplateSource))

	templateFnMap = template.FuncMap{
		"encodeKey":       crypto.EncodeKey,
		"durationToHuman": util.DurationToHuman,
		"stringsJoin":     strings.Join,
	}

	defaultLimitGET      = rate.Every(time.Second)
	defaultLimitGETBurst = 200
	defaultLimitPUT      = rate.Every(time.Minute)
	defaultLimitPUTBurst = 50
)

// Config is the configuration struct used to configure the client and the server. Some settings only apply to
// the client, others only to the server. Some apply to both. Many (but not all) of these settings can be set either
// via the config file, or via command line parameters.
type Config struct {
	ListenHTTPS            string
	ListenHTTP             string
	ServerAddr                string
	DefaultID                 string
	Key                       *crypto.Key
	KeyFile                   string
	CertFile                  string
	ClipboardName             string
	ClipboardDir              string
	ClipboardSizeLimit        int64
	ClipboardCountLimit       int
	FileSizeLimit             int64
	FileExpireAfterDefault    time.Duration
	FileExpireAfterNonTextMax time.Duration
	FileExpireAfterTextMax    time.Duration
	FileModesAllowed          []string
	ProgressFunc              util.ProgressFunc
	ManagerInterval           time.Duration
	LimitGET                  rate.Limit
	LimitGETBurst             int
	LimitPUT                  rate.Limit
	LimitPUTBurst             int
}

// New returns the default config
func New() *Config {
	return &Config{
		ListenHTTPS:            fmt.Sprintf(":%d", DefaultPort),
		ListenHTTP:             "",
		ServerAddr:                "",
		Key:                       nil,
		KeyFile:                   "",
		CertFile:                  "",
		DefaultID:                 DefaultID,
		ClipboardName:             DefaultClipboardName,
		ClipboardDir:              DefaultClipboardDir,
		ClipboardSizeLimit:        DefaultClipboardSizeLimit,
		ClipboardCountLimit:       DefaultClipboardCountLimit,
		FileSizeLimit:             DefaultFileSizeLimit,
		FileExpireAfterDefault:    DefaultFileExpireAfter,
		FileExpireAfterNonTextMax: DefaultFileExpireAfter,
		FileExpireAfterTextMax:    DefaultFileExpireAfter,
		FileModesAllowed:          strings.Split(DefaultFileModesAllowed, " "),
		ProgressFunc:              nil,
		ManagerInterval:           defaultManagerInterval,
		LimitGET:                  defaultLimitGET,
		LimitGETBurst:             defaultLimitGETBurst,
		LimitPUT:                  defaultLimitPUT,
		LimitPUTBurst:             defaultLimitPUTBurst,
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

// LoadFromFile loads the configuration from a file
func LoadFromFile(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	config, err := loadConfig(file)
	if err != nil {
		return nil, err
	}
	if config.KeyFile == "" {
		config.KeyFile = DefaultKeyFile(filename, true)
	}
	if config.CertFile == "" {
		config.CertFile = DefaultCertFile(filename, true)
	}
	return config, nil
}

func getConfigDir() string {
	overrideConfigDir := os.Getenv(EnvConfigDir)
	if overrideConfigDir != "" {
		return overrideConfigDir
	}
	u, _ := user.Current()
	if u.Uid == "0" {
		return systemConfigDir
	}
	return util.ExpandHome(userConfigDir)
}

func loadConfig(reader io.Reader) (*Config, error) {
	config := New()
	raw, err := loadRawConfig(reader)
	if err != nil {
		return nil, err
	}

	listenAddr, ok := raw["ListenAddr"]
	if ok {
		config.ListenHTTP = ""
		config.ListenHTTPS = ""
		re := regexp.MustCompile(`^(?i)([^:]*:\d+)?(?:/(https?))?`)
		addrs := strings.Split(listenAddr, " ")
		for _, addr := range addrs {
			matches := re.FindStringSubmatch(addr)
			if matches == nil {
				return nil, fmt.Errorf("invalid config value for 'ListenAddr', for address %s", addr)
			}
			proto := "https"
			if len(matches) == 3 {
				proto = strings.ToLower(matches[2])
			}
			if proto == "http" {
				if config.ListenHTTP != "" {
					return nil, fmt.Errorf("invalid config value for 'ListenAddr': HTTP address defined more than once")
				}
				config.ListenHTTP = matches[1]
			} else {
				if config.ListenHTTPS != "" {
					return nil, fmt.Errorf("invalid config value for 'ListenAddr': HTTPS address defined more than once")
				}
				config.ListenHTTPS = matches[1]
			}
		}
	}

	serverAddr, ok := raw["ServerAddr"]
	if ok {
		config.ServerAddr = ExpandServerAddr(serverAddr)
	}

	defaultID, ok := raw["DefaultID"]
	if ok {
		re := regexp.MustCompile(`^[a-z0-9][-_.a-z0-9]*$`)
		if defaultID != "" && !re.MatchString(defaultID) {
			return nil, fmt.Errorf("invalid config value for 'DefaultID'")
		}
		config.DefaultID = defaultID
	}

	key, ok := raw["Key"]
	if ok {
		config.Key, err = crypto.DecodeKey(key)
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

	clipboardName, ok := raw["ClipboardName"]
	if ok {
		config.ClipboardName = clipboardName
	}

	clipboardDir, ok := raw["ClipboardDir"]
	if ok {
		config.ClipboardDir = util.ExpandHome(clipboardDir)
	}

	clipboardSizeLimit, ok := raw["ClipboardSizeLimit"]
	if ok {
		config.ClipboardSizeLimit, err = util.ParseSize(clipboardSizeLimit)
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
		config.FileSizeLimit, err = util.ParseSize(fileSizeLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'FileSizeLimit': %w", err)
		}
	}

	fileExpireAfter, ok := raw["FileExpireAfter"]
	if ok {
		parts := strings.Split(fileExpireAfter, " ")
		config.FileExpireAfterDefault, err = util.ParseDuration(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid config value for 'FileExpireAfter': %w", err)
		}
		if len(parts) > 1 {
			config.FileExpireAfterNonTextMax, err = util.ParseDuration(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid config value for 'FileExpireAfter': %w", err)
			}
		} else {
			config.FileExpireAfterNonTextMax = config.FileExpireAfterDefault
		}
		if len(parts) > 2 {
			config.FileExpireAfterTextMax, err = util.ParseDuration(parts[2])
			if err != nil {
				return nil, fmt.Errorf("invalid config value for 'FileExpireAfter': %w", err)
			}
		} else {
			config.FileExpireAfterTextMax = config.FileExpireAfterNonTextMax
		}
		if config.FileExpireAfterNonTextMax > 0 && config.FileExpireAfterDefault > config.FileExpireAfterNonTextMax {
			return nil, fmt.Errorf("invalid config value for 'FileExpireAfter': default value cannot be larger than max")
		}
		if config.FileExpireAfterTextMax > 0 && config.FileExpireAfterNonTextMax > config.FileExpireAfterTextMax {
			return nil, fmt.Errorf("invalid config value for 'FileExpireAfter': max value cannot be larger than text-max")
		}
	}

	fileModesAllowed, ok := raw["FileModesAllowed"]
	if ok {
		modes := strings.Split(fileModesAllowed, " ")
		if len(modes) == 0 || len(modes) > 2 {
			return nil, fmt.Errorf("invalid config value for 'FileModesAllowed': max two, but at least one value expected")
		}
		for _, m := range modes {
			if m != FileModeReadOnly && m != FileModeReadWrite {
				return nil, fmt.Errorf("invalid config value for 'FileModesAllowed': %s", m)
			}
		}
		config.FileModesAllowed = modes
	}

	return config, nil
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
