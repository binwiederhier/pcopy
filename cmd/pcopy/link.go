package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"time"
)

var cmdLink = &cli.Command{
	Name:      "link",
	Usage:     "Generate direct download link to clipboard content",
	UsageText: "pcopy link [OPTIONS..] [[CLIPBOARD]:[ID]]",
	Action:    execLink,
	Category:  categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "alternate config file (default is based on clipboard name)"},
		&cli.DurationFlag{Name: "ttl", Aliases: []string{"t"}, DefaultText: "6h", Usage: "duration the link is valid for, only protected clipboards"},
	},
	Description: `Generates a link for the given clipboard file that can be used to share
with others.

For password-protected clipboards, the link is temporary and only valid until
the time-to-live (--ttl) expires.

Examples:
  pcopy link                 # Generates link for the default clipboard
  pcopy link -ttl 1h myfile  # Generates link 'myfile' in defalt clipboard that expires after 1h
  pcopy link work:           # Generates link for default file in clipboard 'work'`,
}

func execLink(c *cli.Context) error {
	config, clipboard, id, ttl := parseLinkArgs(c)
	url, err := pcopy.GenerateClipURL(config, id, ttl)
	if err != nil {
		return err
	}

	fmt.Printf("# Temporary download link for file '%s' in clipboard '%s'\n", id, clipboard)
	if config.CertFile != "" {
		fmt.Println("# Warning: This clipboard uses a self-signed TLS certificate. Browsers will show a warning.")
		// TODO print cert fingerprint!
	}
	fmt.Println()
	fmt.Println(url)
	fmt.Println()

	return nil
}

func parseLinkArgs(c *cli.Context) (*pcopy.Config, string, string, time.Duration) {
	configFileOverride := c.String("config")
	ttl := c.Duration("ttl")

	// Parse clipboard and file
	clipboard, id := pcopy.DefaultClipboard, pcopy.DefaultID
	if c.NArg() > 0 {
		clipboard, id = parseClipboardAndID(c.Args().First(), configFileOverride)
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig(configFileOverride, clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return config, clipboard, id, ttl
}
