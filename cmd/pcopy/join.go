package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

	// Read basic info from server
	client := pcopy.NewClient(&pcopy.Config{
		ServerAddr: serverAddr,
	})

	info, err := client.Info()
	if err != nil {
		fail(err)
	}

	// Read password (if server is secured with key)
	var key []byte

	if info.Salt != nil {
		fmt.Print("Enter password to join clipboard: ")

		password, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			fail(err)
		}
		fmt.Print("\r")

		// Verify that password was correct
		key = pcopy.DeriveKey(password, info.Salt)
		err = client.Verify(info.Certs, key)
		if err != nil {
			fail(errors.New(fmt.Sprintf("Failed to join clipboard, %s", err.Error())))
		}
	}

	// Save config file
	configFile = pcopy.GetConfigFileForAlias(alias)
	configDir := filepath.Dir(configFile)

	if err := os.MkdirAll(configDir, 0744); err != nil {
		fail(err)
	}

	var config string
	if key != nil {
		keyEncoded := pcopy.EncodeKey(key, info.Salt)
		config = fmt.Sprintf("ServerAddr %s\nKey %s\n", serverAddr, keyEncoded)
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

	printInstructions(configFile, alias, serverAddr, info)
}

func printInstructions(configFile string, alias string, serverAddr string, info *pcopy.Info) {
	aliasPrefix := ""
	if alias != "default" {
		aliasPrefix = fmt.Sprintf("%s:", alias)
	}

	fmt.Printf("Successfully joined clipboard, config written to %s\n", configFile)
	if info.Certs != nil {
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
	if info.Certs != nil {
		pinnedPublicKeys := ""
		if hashes, err := calculatePublicKeyHashes(info.Certs); err == nil {
			pinnedPublicKeys = fmt.Sprintf("--pinnedpubkey %s ", strings.Join(hashes, ";"))
			fmt.Println("To easily join on other computers, you can run this command (despite the -k option,")
			fmt.Println("the curl command is secure, since the public key is pinned):")
			fmt.Println()
			fmt.Printf("  $ sudo bash -c 'curl -sk %shttps://%s/install | sh'\n", pinnedPublicKeys, serverAddr)
		} else {
			fmt.Println("To easily join on other computers, you can run this command (due to the -k option,")
			fmt.Println("this curl command may be intercepted):")
			fmt.Println()
			fmt.Printf("  $ sudo bash -c 'curl -sk %shttps://%s/install | sh'\n", pinnedPublicKeys, serverAddr)
		}
	} else {
		fmt.Println("To easily join on other computers, you can run this command:")
		fmt.Println()
		fmt.Printf("  $ sudo bash -c 'curl -s https://%s/install | sh'\n", serverAddr)
	}
	fmt.Println()
}

func calculatePublicKeyHashes(certs []*x509.Certificate) ([]string, error) {
	hashes := make([]string, len(certs))

	for i, cert := range certs {
		derCert, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		hash.Write(derCert)
		hashes[i] = fmt.Sprintf("sha256//%s", base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	}

	return hashes, nil
}
