package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"pcopy"
)

func execServe()  {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configName := flags.String("config", "server", "Alternate config name")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	config, err := loadConfig(*configName)
	if err != nil {
		fail(err)
	}
	if config.CacheDir == "" {
		config.CacheDir = getDefaultCacheDir()
	}
	if config.ListenAddr == "" {
		fail(errors.New("listen address missing, add 'ListenAddr' to config"))
	}
	if config.KeyFile == "" {
		config.KeyFile = filepath.Join(getConfigDir(), *configName + ".key")
		if _, err := os.Stat(config.KeyFile); err != nil {
			fail(errors.New("key file missing, add 'KeyFile' to config"))
		}
	}
	if config.CertFile == "" {
		config.CertFile = filepath.Join(getConfigDir(), *configName + ".crt")
		if _, err := os.Stat(config.CertFile); err != nil {
			fail(errors.New("cert file missing, add 'CertFile' to config"))
		}
	}
	if config.Key == nil {
		fail(errors.New("key missing, add 'Key' to config"))
	}

	log.Printf("Starting %s, using cache %s", *configName, config.CacheDir)
	log.Printf("Listening on %s", config.ListenAddr)

	server := pcopy.NewServer(config)
	if err := server.ListenAndServeTLS(); err != nil {
		fail(err)
	}
}
