package cmd

import (
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/server"
	"log"
	"os"
)

const defaultServerClipboardName = "server"

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
/etc/pcopy/server.conf (if root). Config options can be overridden using the command line options.

To generate a new config file, you may want to use the 'pcopy setup' command.

Examples:
  pcopy serve                      # Starts server in the foreground
  pcopy serve --listen-https :9999 # Starts server with alternate port
  PCOPY_KEY=.. pcopy serve         # Starts server with alternate key (see 'pcopy keygen')

To override or specify the remote server key, you may pass the PCOPY_KEY variable.`,
}

func execServe(c *cli.Context) error {
	files := c.StringSlice("config")
	listenHTTPS := c.String("listen-https")
	listenHTTP := c.String("listen-http")
	serverAddr := c.String("server")
	keyFile := c.String("key")
	certFile := c.String("cert")
	clipboardDir := c.String("dir")

	var err error
	var configs []*config.Config
	if len(files) == 0 {
		configs, err = loadDefaultServerConfigWithOverrides(listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir)
	} else {
		configs, err = loadServerConfigsFromFilesWithOverrides(files, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir)
	}
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		return cli.Exit("No valid config files found. Exiting", 1)
	}
	return server.Serve(configs...)
}

func loadDefaultServerConfigWithOverrides(listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir string) ([]*config.Config, error) {
	store := config.NewStore()
	filename := store.FileFromName(defaultServerClipboardName)

	var err error
	var conf *config.Config
	if stat, _ := os.Stat(filename); stat != nil {
		log.Printf("Loading config from %s", filename)
		conf, err = config.LoadFromFile(filename)
		if err != nil {
			return nil, err
		}
	} else {
		log.Printf("No server config file found, using command line arguments")
		conf = config.New()
	}
	conf, err = maybeOverrideOptions(conf, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir)
	if err != nil {
		return nil, err
	}
	return []*config.Config{conf}, nil
}

func loadServerConfigsFromFilesWithOverrides(files []string, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir string) ([]*config.Config, error) {
	configs := make([]*config.Config, 0)
	for _, filename := range files {
		if _, err := os.Stat(filename); err != nil {
			return nil, err
		}
		log.Printf("Loading config from %s", filename)
		conf, err := config.LoadFromFile(filename)
		if err != nil {
			return nil, err
		}
		conf, err = maybeOverrideOptions(conf, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir)
		if err != nil {
			return nil, err
		}
		configs = append(configs, conf)
	}
	return configs, nil
}

func maybeOverrideOptions(conf *config.Config, listenHTTPS, listenHTTP, serverAddr, keyFile, certFile, clipboardDir string) (*config.Config, error) {
	if listenHTTPS != "" {
		conf.ListenHTTPS = listenHTTPS
	}
	if listenHTTP != "" {
		conf.ListenHTTP = listenHTTP
	}
	if serverAddr != "" {
		conf.ServerAddr = config.ExpandServerAddr(serverAddr)
	}
	if clipboardDir != "" {
		conf.ClipboardDir = clipboardDir
	}
	if keyFile != "" {
		conf.KeyFile = keyFile
	}
	if certFile != "" {
		conf.CertFile = certFile
	}
	if os.Getenv(config.EnvKey) != "" {
		var err error
		conf.Key, err = crypto.DecodeKey(os.Getenv(config.EnvKey))
		if err != nil {
			return nil, err
		}
	}
	return conf, nil
}
