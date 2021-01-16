package main

import (
	"crypto/x509"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"os"
	"strings"
	"time"
)

var cmdLink = &cli.Command{
	Name:      "link",
	Aliases:   []string{"n"},
	Usage:     "Generate direct download link to clipboard content",
	UsageText: "pcopy link [OPTIONS..] [[CLIPBOARD]:[ID]]",
	Action:    execLink,
	Category:  categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "load config file from `FILE`"},
		&cli.DurationFlag{Name: "ttl", Aliases: []string{"t"}, DefaultText: "6h", Value: 6 * time.Hour, Usage: "set duration the link is valid for to `TTL` (only protected)"},
	},
	Description: `Generates a link for the given clipboard file that can be used to share
with others.

For password-protected clipboards, the link is temporary and only valid until
the time-to-live (--ttl) expires.

Examples:
  pcopy link                  # Generates link for the default clipboard
  pcopy link --ttl 1h myfile  # Generates link 'myfile' in defalt clipboard that expires after 1h
  pcopy link work:            # Generates link for default file in clipboard 'work'`,
}

func execLink(c *cli.Context) error {
	config, id, ttl, err := parseLinkArgs(c)
	if err != nil {
		return err
	}
	if config.ServerAddr == "" {
		return fmt.Errorf("clipboard does not exist")
	}
	return printLinks(config, id, ttl)
}

func printLinks(config *pcopy.Config, id string, ttl time.Duration) error {
	url, err := config.GenerateClipURL(id, ttl)
	if err != nil {
		return err
	}
	var cert *x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			cert, err = pcopy.LoadCertFromFile(config.CertFile)
			if err != nil {
				return err
			}
		}
		eprintf("# Direct link (valid for %s, warning: browsers will show a warning!)\n", pcopy.DurationToHuman(ttl))
		// TODO print cert fingerprint!
	} else {
		eprintf("# Direct link (valid for %s)\n", pcopy.DurationToHuman(ttl))
	}
	eprintln(url)

	eprintln()
	eprintln("# Paste via pcopy (you may need a prefix)")
	if id == pcopy.DefaultID {
		eprintln("ppaste")
	} else {
		eprintf("ppaste %s", id)
	}

	eprintln()
	eprintln("# Paste via curl")
	cmd, err := curlCommand(id, config, cert, ttl)
	if err != nil {
		return err
	}
	eprintln(cmd)

	return nil
}

func parseLinkArgs(c *cli.Context) (*pcopy.Config, string, time.Duration, error) {
	configFileOverride := c.String("config")
	ttl := c.Duration("ttl")

	// Parse clipboard and file
	clipboard, id := pcopy.DefaultClipboard, pcopy.DefaultID
	if c.NArg() > 0 {
		var err error
		clipboard, id, err = parseClipboardAndID(c.Args().First(), configFileOverride)
		if err != nil {
			return nil, "", 0, err
		}
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig(configFileOverride, clipboard)
	if err != nil {
		return nil, "", 0, err
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return config, id, ttl, nil
}

func curlCommand(cmd string, config *pcopy.Config, cert *x509.Certificate, ttl time.Duration) (string, error) {
	args := make([]string, 0)
	if cert == nil {
		args = append(args, "-sSL")
	} else {
		if hash, err := pcopy.CalculatePublicKeyHash(cert); err == nil {
			hashBase64 := pcopy.EncodeCurlPinnedPublicKeyHash(hash)
			args = append(args, "-sSLk", fmt.Sprintf("--pinnedpubkey %s", hashBase64))
		} else {
			args = append(args, "-sSLk")
		}
	}
	path := fmt.Sprintf("/%s", cmd)
	url, err := config.GenerateURL(path, ttl)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("curl %s '%s'", strings.Join(args, " "), url), nil
}
