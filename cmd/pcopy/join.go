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
	if err := flags.Parse(args); err != nil {
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
	//fmt.Println("To join this clipboard, a password is required.")
	fmt.Print("Enter password to join clipboard: ")

	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Print("\r")

	client := pcopy.NewClient(&pcopy.Config{
		ServerAddr: serverAddr,
	})

	info, err := client.Info()
	if err != nil {
		fail(err)
	}

	// Verify that password was correct
	key := pcopy.DeriveKey(password, info.Salt)
	err = client.Verify(info.Cert, key)
	if err != nil {
		fail(errors.New(fmt.Sprintf("Failed to join clipboard, %s", err.Error())))
	}

	// Save config file and cert
	configFile = pcopy.GetConfigFileForAlias(alias)
	configDir := filepath.Dir(configFile)
	certFile := filepath.Join(configDir, alias + ".crt")

	if err := os.MkdirAll(configDir, 0744); err != nil {
		fail(err)
	}

	keyEncoded := pcopy.EncodeKey(key, info.Salt)
	config := fmt.Sprintf("ServerAddr %s\nKey %s\n", serverAddr, keyEncoded)
	if err := ioutil.WriteFile(configFile, []byte(config), 0644); err != nil {
		fail(err)
	}
	if info.Cert != nil {
		if err := ioutil.WriteFile(certFile, info.Cert, 0644); err != nil {
			fail(err)
		}
	}

	aliasPrefix := ""
	if alias != "default" {
		aliasPrefix = fmt.Sprintf("%s:", alias)
	}

	fmt.Printf("Successfully joined clipboard, config written to %s\n", configFile)
	if info.Cert != nil {
		fmt.Println()
		fmt.Println("Warning: Please be aware that the remote certificate was self-signed and has been pinned.")
		fmt.Println("Future communication will be secure, but joining could have been intercepted.")
	}
	fmt.Println()
	fmt.Println("You may now use 'pcopy copy' and 'pcopy paste', like this:")
	fmt.Println()
	fmt.Printf("  $ echo 'some text to copy' | pcopy copy %s\n", aliasPrefix)
	fmt.Printf("  $ pcopy paste %s\n", aliasPrefix)
	fmt.Println()
	fmt.Printf("  $ pcopy copy %smyfile < myfile.txt\n", aliasPrefix)
	fmt.Printf("  $ pcopy paste %smyfile > myfile.txt\n", aliasPrefix)
	fmt.Println()
	fmt.Println("You may also want to install the shortcuts 'pcp' and 'ppaste' like so:")
	fmt.Println()
	fmt.Println("  $ sudo pcopy install")
	fmt.Println()
	fmt.Println("To easily join on other computers, you can run this command:")
	fmt.Println()
	// TODO --pinnedpubkey
	if info.Cert != nil {
		fmt.Printf("  $ sudo bash -c 'curl -sk https://%s/install | sh'\n", serverAddr)
	} else {
		fmt.Printf("  $ sudo bash -c 'curl -s https://%s/install | sh'\n", serverAddr)
	}
	fmt.Println()
}
