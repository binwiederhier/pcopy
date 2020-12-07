package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"pcopy"
	"syscall"
)

func execServe(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	flags.Usage = func() { showServeUsage(flags) }
	configFileOverride := flags.String("config", "", "Alternate config file")
	listenAddr := flags.String("listen", "", "Address and port to use to bind the server")
	serverAddr := flags.String("addr", "", "Server address to be advertised to clients")
	keyFile := flags.String("key", "", "Private key file")
	certFile := flags.String("cert", "", "Certificate file")
	cacheDir := flags.String("cache", "", "Cache dir")
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
	if *cacheDir != "" {
		config.CacheDir = *cacheDir
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
	if config.Key == nil {
		log.Printf("Listening on %s (INSECURE MODE)\n", config.ListenAddr)
	} else {
		log.Printf("Listening on %s\n", config.ListenAddr)
	}

	if err := pcopy.Serve(config); err != nil {
		fail(err)
	}
}

func showServeUsage(flags *flag.FlagSet) {
	fmt.Println("Usage: pcopy serve [OPTIONS..]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Start pcopy server and listen for incoming requests.")
	fmt.Println()
	fmt.Println("  The command will load a the clipboard config from ~/.config/pcopy/server.conf or")
	fmt.Println("  /etc/pcopy/server.conf. Config options can be overridden using the command line options.")
	fmt.Println()
	fmt.Println("  To generate a new config file, you may want to use the 'pcopy setup-server' command.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy serve                 # Starts server in the foreground")
	fmt.Println("  pcopy serve -listen :9999   # Starts server with alternate port")
	fmt.Println("  PCOPY_KEY=.. pcopy serve    # Starts server with alternate key (see 'pcopy keygen')")
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	fmt.Println()
	fmt.Println("To override or specify the remote server key, you may pass the PCOPY_KEY variable.")
	syscall.Exit(1)
}
