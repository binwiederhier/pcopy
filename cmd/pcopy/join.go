package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"path/filepath"
	"pcopy"
	"strings"
	"syscall"
)

func execJoin() {
	flags := flag.NewFlagSet("join", flag.ExitOnError)
	force := flags.Bool("force", false, "Overwrite config if it already exists")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	if flags.NArg() < 1 {
		usage()
	}

	alias := "default"
	serverAddr := flags.Arg(0)

	if flags.NArg() > 1 {
		alias = flags.Arg(1)
	}

	if !strings.Contains(serverAddr, ":") {
		serverAddr = fmt.Sprintf("%s:1986", serverAddr)
	}

	configFile := pcopy.FindConfigFile(alias)
	if configFile != "" && !*force {
		fail(errors.New(fmt.Sprintf("config file %s already exists, use -force to override", configFile)))
	}

	// Read password
	fmt.Print("Enter Password: ")
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Println()

	client := pcopy.NewClient(&pcopy.Config{
		ServerAddr: serverAddr,
	})

	info, err := client.Info()
	if err != nil {
		fail(err)
	}

	// Verify
	// TODO verify
	
	// Save config file and cert
	configFile = pcopy.GetConfigFileForAlias(alias)
	configDir := filepath.Dir(configFile)
	certFile := filepath.Join(configDir, alias + ".crt")

	if err := os.MkdirAll(configDir, 0744); err != nil {
		fail(err)
	}

	keyEncoded := pcopy.DeriveKey(password, info.Salt)
	config := fmt.Sprintf("ServerAddr %s\nKey %s\n", serverAddr, keyEncoded)
	if err := ioutil.WriteFile(configFile, []byte(config), 0644); err != nil {
		fail(err)
	}
	if info.Cert != "" {
		if err := ioutil.WriteFile(certFile, []byte(info.Cert), 0644); err != nil {
			fail(err)
		}
	}

	fmt.Printf("Joined %s, config written to %s\n", alias, configFile)
}
