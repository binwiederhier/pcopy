package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"pcopy"
)

func execInvite(args []string)  {
	config, alias := parseInviteArgs("invite", args)

	var certs []*x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			certs, err = pcopy.LoadCerts(config.CertFile)
			if err != nil {
				fail(err)
			}
		}
	}

	fmt.Printf("# Instructions for clipboard '%s'\n", alias)
	fmt.Println()
	fmt.Println("# Install pcopy on other computers:")
	fmt.Printf("%s\n", curlCommand("install", config.ServerAddr, certs, nil))

	fmt.Println()
	fmt.Println("# Install and join this clipboard on other computers:")
	fmt.Printf("%s\n", curlCommand("join", config.ServerAddr, certs, config.Key))
	fmt.Println()
}


func parseInviteArgs(command string, args []string) (*pcopy.Config, string) {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse alias and file
	alias := "default"
	if flags.NArg() > 0 {
		alias = flags.Arg(0)
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig("", alias)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile)
	}

	return config, alias
}
