package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"pcopy"
	"strings"
)

func execServe(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configFileOverride := flags.String("config", "", "Alternate config file")
	listenAddr := flags.String("listen", "", "Listen address")
	keyFile := flags.String("keyfile", "", "Private key file")
	certFile := flags.String("certfile", "", "Certificate file")
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
			config.KeyFile = strings.TrimSuffix(configFile, ".conf") + ".key"
		}
		if config.CertFile == "" {
			config.CertFile = strings.TrimSuffix(configFile, ".conf") + ".crt"
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

	// Validate
	if config.ListenAddr == "" {
		fail(errors.New("listen address missing, add 'ListenAddr' to config or pass -listen"))
	}
	if config.KeyFile == "" {
		fail(errors.New("private key file missing, add 'KeyFile' to config or pass -keyfile"))
	}
	if config.CertFile == "" {
		fail(errors.New("certificate file missing, add 'CertFile' to config or pass -certfile"))
	}
	if unix.Access(config.CacheDir, unix.W_OK) != nil {
		fail(errors.New(fmt.Sprintf("cache dir %s not writable by user", config.CacheDir)))
	}

	// Start server
	if config.Key == nil {
		log.Printf("Listening on %s (INSECURE MODE, no 'Key' defined)\n", config.ListenAddr)
	} else {
		log.Printf("Listening on %s\n", config.ListenAddr)
	}

	if err := pcopy.Serve(config); err != nil {
		fail(err)
	}
}
