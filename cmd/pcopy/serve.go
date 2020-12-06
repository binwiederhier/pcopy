package main

import (
	"flag"
	"log"
	"os"
	"pcopy"
)

func execServe(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configFileOverride := flags.String("config", "", "Alternate config file")
	listenAddr := flags.String("listen", "", "Listen address")
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
			config.KeyFile = pcopy.DefaultKeyFile(configFile)
		}
		if config.CertFile == "" {
			config.CertFile = pcopy.DefaultCertFile(configFile)
		}
	}

	// Command line overrides
	if *listenAddr != "" {
		config.ListenAddr = *listenAddr
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
