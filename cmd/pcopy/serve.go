package main

import (
	"flag"
	"heckel.io/pcopy"
	"os"
	"syscall"
)

func execServe(args []string) {
	flags := flag.NewFlagSet("pcopy serve", flag.ExitOnError)
	flags.Usage = func() { showServeUsage(flags) }
	configFileOverride := flags.String("config", "", "Alternate config file")
	listenAddr := flags.String("listen", "", "Address and port to use to bind the server")
	serverAddr := flags.String("addr", "", "Server address to be advertised to clients")
	keyFile := flags.String("key", "", "Private key file for TLS connections")
	certFile := flags.String("cert", "", "Certificate file for TLS connections")
	clipboardDir := flags.String("dir", "", "Clipboard directory")
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig(*configFileOverride, "server")
	if err != nil {
		fail(err)
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
	if *listenAddr != "" {
		config.ListenAddr = *listenAddr
	}
	if *serverAddr != "" {
		config.ServerAddr = pcopy.ExpandServerAddr(*serverAddr)
	}
	if *clipboardDir != "" {
		config.ClipboardDir = *clipboardDir
	}
	if *keyFile != "" {
		config.KeyFile = *keyFile
	}
	if *certFile != "" {
		config.CertFile = *certFile
	}
	if os.Getenv("PCOPY_KEY") != "" {
		config.Key, err = pcopy.DecodeKey(os.Getenv("PCOPY_KEY"))
		if err != nil {
			fail(err)
		}
	}

	// Start server
	if err := pcopy.Serve(config); err != nil {
		fail(err)
	}
}

func showServeUsage(flags *flag.FlagSet) {
	eprintln("Usage: pcopy serve [OPTIONS..]")
	eprintln()
	eprintln("Description:")
	eprintln("  Start pcopy server and listen for incoming requests.")
	eprintln()
	eprintln("  The command will load a the clipboard config from ~/.config/pcopy/server.conf or")
	eprintln("  /etc/pcopy/server.conf. Config options can be overridden using the command line options.")
	eprintln()
	eprintln("  To generate a new config file, you may want to use the 'pcopy setup-server' command.")
	eprintln()
	eprintln("Examples:")
	eprintln("  pcopy serve                 # Starts server in the foreground")
	eprintln("  pcopy serve -listen :9999   # Starts server with alternate port")
	eprintln("  PCOPY_KEY=.. pcopy serve    # Starts server with alternate key (see 'pcopy keygen')")
	eprintln()
	eprintln("Options:")
	flags.PrintDefaults()
	eprintln()
	eprintln("To override or specify the remote server key, you may pass the PCOPY_KEY variable.")
	syscall.Exit(1)
}
