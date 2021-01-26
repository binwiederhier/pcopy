package main

import (
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"os"
)

var cmdServe = &cli.Command{
	Name:     "serve",
	Usage:    "Start pcopy server",
	Action:   execServe,
	Category: categoryServer,
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "config", Aliases: []string{"c"}, Usage: "load config file from `FILE`"},
		&cli.StringFlag{Name: "listen-https", Aliases: []string{"l"}, Usage: "set bind address for HTTPS connections to `[ADDR]:PORT`"},
		&cli.StringFlag{Name: "listen-http", Aliases: []string{"L"}, Usage: "set bind address for HTTP connections to `[ADDR]:PORT`"},
		&cli.StringFlag{Name: "server", Aliases: []string{"S"}, Usage: "set server address to be advertised to clients to `ADDR[:PORT]` (default port: 2586)"},
		&cli.StringFlag{Name: "key", Aliases: []string{"K"}, Usage: "set private key file for TLS connections to `KEY`"},
		&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Usage: "set certificate file for TLS connections to `CERT`"},
		&cli.StringFlag{Name: "dir", Aliases: []string{"d"}, Usage: "set clipboard directory to keep clipboard contents to `DIR`"},
	},
	Description: `Start pcopy server and listen for incoming requests.

The command will load a the clipboard config from ~/.config/pcopy/server.conf or
/etc/pcopy/server.conf. Config options can be overridden using the command line options.

To generate a new config file, you may want to use the 'pcopy setup' command.

Examples:
  pcopy serve                      # Starts server in the foreground
  pcopy serve --listen-https :9999 # Starts server with alternate port
  PCOPY_KEY=.. pcopy serve         # Starts server with alternate key (see 'pcopy keygen')

To override or specify the remote server key, you may pass the PCOPY_KEY variable.`,
}

func execServe(c *cli.Context) error {
	configFiles := c.StringSlice("config")
	listenHTTPS := c.String("listen-https")
	listenHTTP := c.String("listen-http")
	serverAddr := c.String("server")
	keyFile := c.String("key")
	certFile := c.String("cert")
	clipboardDir := c.String("dir")

	// TODO this is weird
	if len(configFiles) == 0 {
		config, err := parseServeConfig("", listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir)
		if err != nil {
			return err
		}
		return pcopy.Serve(config)
	}
	configs := make([]*pcopy.Config, len(configFiles))
	for i, filename := range configFiles {
		config, err := parseServeConfig(filename, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir)
		if err != nil {
			return err
		}
		configs[i] = config
	}
	return pcopy.Serve(configs...)
}

func parseServeConfig(filename, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir string) (*pcopy.Config, error) {
	// Load config
	configFile, config, err := parseAndLoadConfig(filename, "server")
	if err != nil {
		return nil, err
	}

	// Load defaults
	if configFile != "" {
		if config.KeyFile == "" {
			config.KeyFile = pcopy.DefaultKeyFile(configFile, true)
		}
		if config.CertFile == "" {
			config.CertFile = pcopy.DefaultCertFile(configFile, true)
		}
	}

	// Command line overrides
	if listenHTTPS != "" {
		config.ListenHTTPS = listenHTTPS
	}
	if listenHTTP != "" {
		config.ListenHTTP = listenHTTP
	}
	if serverAddr != "" {
		config.ServerAddr = pcopy.ExpandServerAddr(serverAddr)
	}
	if clipboardDir != "" {
		config.ClipboardDir = clipboardDir
	}
	if keyFile != "" {
		config.KeyFile = keyFile
	}
	if certFile != "" {
		config.CertFile = certFile
	}
	if os.Getenv("PCOPY_KEY") != "" {
		config.Key, err = pcopy.DecodeKey(os.Getenv("PCOPY_KEY"))
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}
