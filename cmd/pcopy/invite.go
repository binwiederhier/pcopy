package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"pcopy"
	"strings"
)

func execInvite(args []string)  {
	config, alias := parseInviteArgs("invite", args)

	var certs []*x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			certs, err = pcopy.LoadCertsFromFile(config.CertFile)
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

func curlCommand(cmd string, serverAddr string, certs []*x509.Certificate, key *pcopy.Key) string {
	args := make([]string, 0)
	if key != nil {
		auth, err := pcopy.GenerateAuthHMAC(key.Bytes, http.MethodGet, fmt.Sprintf("/%s", cmd))
		if err != nil {
			fail(err)
		}
		args = append(args, fmt.Sprintf("-H \"Authorization: %s\"", auth))
	}
	if certs == nil {
		args = append(args, "-s")
	} else {
		if hashes, err := calculatePublicKeyHashes(certs); err == nil {
			args = append(args, "-sk", fmt.Sprintf("--pinnedpubkey %s", strings.Join(hashes, ";")))
		} else {
			args = append(args, "-sk")
		}
	}
	return fmt.Sprintf("sudo bash -c 'curl %s https://%s/%s | sh'", strings.Join(args, " "), serverAddr, cmd)
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
