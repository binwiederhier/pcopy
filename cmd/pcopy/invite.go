package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"heckel.io/pcopy"
	"strings"
	"syscall"
)

func execInvite(args []string)  {
	config, alias := parseInviteArgs(args)

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

func parseInviteArgs(args []string) (*pcopy.Config, string) {
	flags := flag.NewFlagSet("invite", flag.ExitOnError)
	flags.Usage = showInviteUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and file
	clipboard := pcopy.DefaultClipboard
	if flags.NArg() > 0 {
		clipboard = flags.Arg(0)
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig("", clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return config, clipboard
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

func showInviteUsage() {
	fmt.Println("Usage: pcopy invite [OPTIONS..] [CLIPBOARD]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Generates commands that can be shared with others so they can easily install")
	fmt.Println("  pcopy, and/or join this clipboard. CLIPBOARD is the name of the clipboard for")
	fmt.Println("  which to generates the commands (default is 'default').")
	fmt.Println()
	fmt.Println("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	fmt.Println("  /etc/pcopy/$CLIPBOARD.conf. If not config exists, it will fail.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy invite         # Generates links for the default clipboard")
	fmt.Println("  pcopy invite work    # Generates links for the clipboard called 'work'")
	syscall.Exit(1)
}