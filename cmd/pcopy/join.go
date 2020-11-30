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
		printSyntaxAndExit()
	}

	alias := "default"
	serverAddr := flags.Arg(0)

	if flags.NArg() > 1 {
		alias = flags.Arg(1)
	}

	if !strings.Contains(serverAddr, ":") {
		serverAddr = fmt.Sprintf("%s:1986", serverAddr)
	}

	userConfigFile := filepath.Join(os.ExpandEnv(userConfigDir), alias + ".conf")
	systemConfigFile := filepath.Join(systemConfigDir, alias + ".conf")

	if _, err := os.Stat(userConfigFile); err == nil && !*force {
		fail(errors.New("config file " + userConfigFile + " already exists, use -force to override"))
	} else if _, err := os.Stat(systemConfigFile); err == nil && !*force {
		fail(errors.New("config file " + systemConfigFile + " already exists, use -force to override"))
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

	// Save config file and cert
	configDir := getConfigDir()
	configFile := filepath.Join(configDir, alias + ".conf")
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

	fmt.Printf("Joined %s, config written to %s, cert at %s\n", alias, configFile, certFile)
}
