package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"heckel.io/pcopy"
	"os"
	"strings"
	"syscall"
	"time"
)

func execInvite(args []string) {
	config, clipboard, ttl := parseInviteArgs(args)

	// FIXME Fail when clipboard that is passed is invalid

	var certs []*x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			certs, err = pcopy.LoadCertsFromFile(config.CertFile)
			if err != nil {
				fail(err)
			}
		}
	}

	fmt.Printf("# Instructions for clipboard '%s'\n", clipboard)
	fmt.Println()
	fmt.Println("# Install pcopy on other computers (as root):")
	fmt.Printf("%s | sudo sh\n", curlCommand("install", config, certs, 0))

	fmt.Println()
	fmt.Println("# Join this clipboard on other computers:")
	fmt.Printf("%s | sh\n", curlCommand("join", config, certs, ttl))
	fmt.Println()
}

func parseInviteArgs(args []string) (*pcopy.Config, string, time.Duration) {
	flags := flag.NewFlagSet("pcopy invite", flag.ExitOnError)
	configFileOverride := flags.String("config", "", "Alternate config file (default is based on clipboard name)")
	ttl := flags.Duration("ttl", time.Hour*24, "Defines the commands are valid for, only protected clipboards")
	flags.Usage = func() { showInviteUsage(flags) }
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and file
	clipboard := pcopy.DefaultClipboard
	if flags.NArg() > 0 {
		clipboard = flags.Arg(0)
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig(*configFileOverride, clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return config, clipboard, *ttl
}

func curlCommand(cmd string, config *pcopy.Config, certs []*x509.Certificate, ttl time.Duration) string {
	args := make([]string, 0)
	if certs == nil {
		args = append(args, "-sSL")
	} else {
		if hashes, err := calculatePublicKeyHashes(certs); err == nil {
			args = append(args, "-sSLk", fmt.Sprintf("--pinnedpubkey %s", strings.Join(hashes, ";")))
		} else {
			args = append(args, "-sSLk")
		}
	}
	path := fmt.Sprintf("/%s", cmd)
	url, err := pcopy.GenerateUrl(config, path, ttl)
	if err != nil {
		fail(err)
	}
	return fmt.Sprintf("curl %s '%s'", strings.Join(args, " "), url)
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

func showInviteUsage(flags *flag.FlagSet) {
	eprintln("Usage: pcopy invite [OPTIONS..] [CLIPBOARD]")
	eprintln()
	eprintln("Description:")
	eprintln("  Generates commands that can be shared with others so they can easily install")
	eprintln("  pcopy, and/or join this clipboard. CLIPBOARD is the name of the clipboard for")
	eprintln("  which to generates the commands (default is 'default').")
	eprintln()
	eprintln("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	eprintln("  /etc/pcopy/$CLIPBOARD.conf. If not config exists, it will fail.")
	eprintln()
	eprintln("Examples:")
	eprintln("  pcopy invite          # Generates commands for the default clipboard")
	eprintln("  pcopy invite -ttl 1h  # Generates commands for the default clipboard, valid for only 1h")
	eprintln("  pcopy invite work     # Generates commands for the clipboard called 'work'")
	eprintln()
	eprintln("Options:")
	flags.PrintDefaults()
	syscall.Exit(1)
}
