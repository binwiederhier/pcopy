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

var cmdInvite = &cli.Command{
	Name:      "invite",
	Usage:     "Generate commands to invite others to join a clipboard",
	UsageText: "pcopy invite [OPTIONS..] [CLIPBOARD]",
	Action:    execInvite,
	Category:  categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "load config file from `FILE`"},
		&cli.DurationFlag{Name: "ttl", Aliases: []string{"t"}, DefaultText: "24h", Usage: "set how long the invite is valid for to `TTL` (only protected)"},
	},
	Description: `Generates commands that can be shared with others so they can easily join 
this clipboard. CLIPBOARD is the name of the clipboard for which to 
generates the commands (default is 'default').

The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or
/etc/pcopy/$CLIPBOARD.conf. If not config exists, it will fail.

Examples:")
  pcopy invite           # Generates commands for the default clipboard
  pcopy invite --ttl 1h  # Generates commands for the default clipboard, valid for only 1h
  pcopy invite work      # Generates commands for the clipboard called 'work'`,
}

func execInvite(c *cli.Context) error {
	configFile, config, clipboard, ttl, err := parseInviteArgs(c)
	if err != nil {
		return err
	}

	if configFile == "" {
		return fmt.Errorf("clipboard '%s' does not exist", clipboard)
	}
	var cert *x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			cert, err = pcopy.LoadCertFromFile(config.CertFile)
			if err != nil {
				return err
			}
		}
	}

	curl, err := curlCommand("join", config, cert, ttl)
	if err != nil {
		return err
	}

	fmt.Printf("# Join clipboard %s (%s) on other computers\n", clipboard, config.ServerAddr)
	fmt.Println()
	fmt.Printf("%s | sh\n", curl)
	fmt.Println()

	return nil
}

func parseInviteArgs(c *cli.Context) (string, *pcopy.Config, string, time.Duration, error) {
	configFileOverride := c.String("config")
	ttl := c.Duration("ttl")

	// Parse clipboard and file
	clipboard := pcopy.DefaultClipboard
	if c.NArg() > 0 {
		clipboard = c.Args().First()
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig(configFileOverride, clipboard)
	if err != nil {
		return "", nil, "", 0, err
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return configFile, config, clipboard, ttl, nil
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
