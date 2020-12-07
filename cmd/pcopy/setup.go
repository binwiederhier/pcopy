package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"pcopy"
	"strings"
	"syscall"
)

func execSetup(args []string) {
	flags := flag.NewFlagSet("setup", flag.ExitOnError)
	flags.Usage = showSetupUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	reader := bufio.NewReader(os.Stdin)
	config := pcopy.DefaultConfig

	fmt.Println("pcopy server setup")
	fmt.Println("--")

	fmt.Println("The listen address is used to bind the local server.")
	fmt.Printf("Listen address (default: %s): ", config.ListenAddr)
	listenAddr := readLine(reader)
	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}
	fmt.Println()

	fmt.Println("The hostname will be used to advertise to clients. It must be resolvable by clients.")
	fmt.Printf("Hostname (default: %s): ", config.ServerAddr)
	serverAddr := readLine(reader)
	if serverAddr == "" {
		config.ServerAddr = serverAddr
	}
	fmt.Println()

	fmt.Println("To protect the server with a key, enter a password. A key will be derived from it.")
	fmt.Print("Password (default: empty): ")
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Println()
	fmt.Println()

	if string(password) != "" {
		config.Key, err = pcopy.GenerateKey(password)
		if err != nil {
			fail(err)
		}
	}

	pemKey, pemCert, err := pcopy.GenerateKeyAndCert()

	// Write config file
	configFile := pcopy.GetConfigFileForAlias("server")
	if err := config.Write(configFile); err != nil {
		fail(err)
	}

	// Write private key file
	keyFile := pcopy.DefaultKeyFile(configFile, false)
	if err := ioutil.WriteFile(keyFile, []byte(pemKey), 0600); err != nil {
		fail(err)
	}

	// Write cert file
	certFile := pcopy.DefaultCertFile(configFile, false)
	if err := ioutil.WriteFile(certFile, []byte(pemCert), 0644); err != nil {
		fail(err)
	}

	fmt.Printf("Server config written to %s, with key/cert file next to it\n", configFile)
}

func readLine(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil {
		fail(err)
	}
	return strings.TrimSpace(line)
}

func showSetupUsage() {
	fmt.Println("Usage: pcopy setup")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Starts an interactive wizard to generate server config, private key and certificate.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy setup")
	syscall.Exit(1)
}
