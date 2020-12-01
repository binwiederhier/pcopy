package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"pcopy"
)

func execServe() {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configFile := flags.String("config", "", "Alternate config file")
	cacheDir := flags.String("cache", "", "Cache dir")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	// Load config
	config, err := pcopy.LoadConfig(*configFile, "server")
	if err != nil {
		fail(err)
	}

	// Command line overrides
	if *cacheDir != "" {
		config.CacheDir = *cacheDir
	}

	// Validate
	if config.ListenAddr == "" {
		fail(errors.New("listen address missing, add 'ListenAddr' to config"))
	}
	if config.Key == nil {
		fail(errors.New("key missing, add 'Key' to config"))
	}
	if unix.Access(config.CacheDir, unix.W_OK) != nil {
		fail(errors.New(fmt.Sprintf("cache dir %s not writable by user", config.CacheDir)))
	}

	// Start server
	log.Printf("Listening on %s", config.ListenAddr)
	if err := pcopy.Serve(config); err != nil {
		fail(err)
	}
}
