package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"os"
	"strings"
	"syscall"
	"time"
)

var cmdInvite = &cli.Command{
	Name:      "invite",
	Usage:     "Generate commands to invite others to join a clipboard",
	UsageText: "pcopy invite [OPTIONS..] [CLIPBOARD]",
	Action:    execInvite,
	Category:  categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "alternate config file (default is based on clipboard name)"},
		&cli.DurationFlag{Name: "ttl", Aliases: []string{"t"}, DefaultText: "24h", Usage: "duration the invitation is valid for, only protected clipboards"},
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
	configFile, config, clipboard, ttl := parseInviteArgs(c)

	if configFile == "" {
		fail(fmt.Errorf("clipboard '%s' does not exist", clipboard))
	}
	var cert *x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			cert, err = pcopy.LoadCertFromFile(config.CertFile)
			if err != nil {
				fail(err)
			}
		}
	}

	fmt.Printf("# Instructions for clipboard '%s'\n", clipboard)
	fmt.Println()
	fmt.Println("# Join this clipboard on other computers:")
	fmt.Printf("%s | sh\n", curlCommand("join", config, cert, ttl))
	fmt.Println()

	return nil
}

func parseInviteArgs(c *cli.Context) (string, *pcopy.Config, string, time.Duration) {
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
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return configFile, config, clipboard, ttl
}

func curlCommand(cmd string, config *pcopy.Config, cert *x509.Certificate, ttl time.Duration) string {
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
	url, err := pcopy.GenerateURL(config, path, ttl)
	if err != nil {
		fail(err)
	}
	return fmt.Sprintf("curl %s '%s'", strings.Join(args, " "), url)
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
