package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
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
	},
	Description: `Retrieves the link for the given clipboard file that can be used to share
with others.

Examples:
  pcopy link                  # Generates link for the default clipboard
  pcopy link work:            # Generates link for default file in clipboard 'work'`,
}

func execLink(c *cli.Context) error {
	config, id, err := parseLinkArgs(c)
	if err != nil {
		return err
	}
	client, err := pcopy.NewClient(config)
	if err != nil {
		return err
	}
	info, err := client.FileInfo(id)
	if err != nil {
		return err
	}
	fmt.Fprint(c.App.ErrWriter, pcopy.FileInfoInstructions(info))
	return nil
}

func parseLinkArgs(c *cli.Context) (*pcopy.Config, string, error) {
	configFileOverride := c.String("config")

	// Parse clipboard and file
	clipboard, id := pcopy.DefaultClipboard, pcopy.DefaultID
	if c.NArg() > 0 {
		var err error
		clipboard, id, err = parseClipboardAndID(c.Args().First(), configFileOverride)
		if err != nil {
			return nil, "", err
		}
	}

	// Load config
	configFile, config, err := parseAndLoadConfig(configFileOverride, clipboard)
	if err != nil {
		return nil, "", cli.Exit("clipboard does not exist", 1)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return config, id, nil
}
