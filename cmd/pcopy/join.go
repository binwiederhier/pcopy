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

func execJoin(args []string) {
	flags := flag.NewFlagSet("join", flag.ExitOnError)
	force := flags.Bool("force", false, "Overwrite config if it already exists")
	auto := flags.Bool("auto", false, "Automatically choose alias")
	if err := flags.Parse(args); err != nil {
		fail(err)
	}
	if flags.NArg() < 1 {
		showHelp()
	}
	if *force && *auto {
		fail(errors.New("cannot use -auto and -force"))
	}

	alias := "default"
	serverAddr := flags.Arg(0)
	if flags.NArg() > 1 {
		alias = flags.Arg(1)
	}

	if !strings.Contains(serverAddr, ":") {
		serverAddr = fmt.Sprintf("%s:%d", serverAddr, pcopy.DefaultPort)
	}

	// Find config file
	var configFile string
	if *auto {
		alias, configFile = pcopy.FindNewConfigFile(alias)
	} else {
		configFile = pcopy.FindConfigFile(alias)
		if configFile != "" && !*force {
			fail(errors.New(fmt.Sprintf("config file %s exists, you may want to specify a different clipboard name, or use -force to override", configFile)))
		}
		configFile = pcopy.GetConfigFileForAlias(alias)
	}

	// Read basic info from server
	client := pcopy.NewClient(&pcopy.Config{
		ServerAddr: serverAddr,
	})

	info, err := client.Info()
	if err != nil {
		fail(err)
	}

	// Read and verify that password was correct (if server is secured with key)
	var key *pcopy.Key

	if info.Salt != nil {
		envKey := os.Getenv("PCOPY_KEY") // TODO document this
		if envKey != "" {
			key, err = pcopy.DecodeKey(envKey)
			if err != nil {
				fail(err)
			}
		} else {
			password := readPassword()
			key = pcopy.DeriveKey(password, info.Salt)
			err = client.Verify(info.Certs, key)
			if err != nil {
				fail(errors.New(fmt.Sprintf("Failed to join clipboard, %s", err.Error())))
			}
		}
	}

	// TODO write config via Config.write()

	// Save config file
	configDir := filepath.Dir(configFile)
	if err := os.MkdirAll(configDir, 0744); err != nil {
		fail(err)
	}

	var config string
	if key != nil {
		config = fmt.Sprintf("ServerAddr %s\nKey %s\n", serverAddr, pcopy.EncodeKey(key))
	} else {
		config = fmt.Sprintf("ServerAddr %s\n", serverAddr)
	}
	if err := ioutil.WriteFile(configFile, []byte(config), 0644); err != nil {
		fail(err)
	}

	// Write self-signed certs (only if Verify didn't work with secure client)
	if info.Certs != nil {
		certFile := filepath.Join(configDir, alias + ".crt")
		certsEncoded, err := pcopy.EncodeCerts(info.Certs)
		if err != nil {
			fail(err)
		}
		if err := ioutil.WriteFile(certFile, certsEncoded, 0644); err != nil {
			fail(err)
		}
	}

	printInstructions(configFile, alias, info)
}

func readPassword() []byte {
	fmt.Print("Enter password to join clipboard: ")
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Print("\r")
	return password
}

func printInstructions(configFile string, alias string, info *pcopy.Info) {
	aliasPrefix := ""
	if alias != "default" {
		aliasPrefix = fmt.Sprintf("%s:", alias)
	}

	if alias == "default" {
		fmt.Printf("Successfully joined clipboard, config written to %s\n", configFile)
	} else {
		fmt.Printf("Successfully joined clipboard as alias '%s', config written to %s\n", alias, configFile)
	}

	if info.Certs != nil {
		fmt.Println()
		fmt.Println("Warning: The TLS certificate was self-signed and has been pinned.")
		fmt.Println("Future communication will be secure, but joining could have been intercepted.")
	}

	fmt.Println()
	if _, err := os.Stat("/usr/bin/pcp"); err == nil {
		fmt.Printf("You may now use 'pcp %s' and 'ppaste %s'. See 'pcopy -h' for usage details.\n", aliasPrefix, aliasPrefix)
	} else {
		fmt.Printf("You may now use 'pcopy copy %s' and 'pcopy paste %s'. See 'pcopy -h' for usage details.\n", aliasPrefix, aliasPrefix)
	}
	fmt.Println("To install pcopy on other computers, or join this clipboard, use 'pcopy invite' command.")
}
