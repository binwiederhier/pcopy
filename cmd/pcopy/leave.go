package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"os"
)

var cmdLeave = &cli.Command{
	Name:      "leave",
	Usage:     "Leave a remote clipboard",
	UsageText: "pcopy leave [OPTIONS..] [CLIPBOARD]",
	Action:    execLeave,
	Category:  categoryClient,
	Description: `Removes the clipboard configuration and certificate (if any) from the config folder.

The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or
/etc/pcopy/$CLIPBOARD.conf. If not config exists, it will fail.

Examples:
  pcopy leave           # Leaves the default clipboard
  pcopy leave work      # Leaves the clipboard called 'work'
`,
}

func execLeave(c *cli.Context) error {
	configFile, clipboard, config := parseLeaveArgs(c)

	if configFile == "" {
		return fmt.Errorf("clipboard '%s' does not exist", clipboard)
	}
	if err := os.Remove(configFile); err != nil {
		return err
	}
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			if err := os.Remove(config.CertFile); err != nil {
				fail(err)
			}
		}
	}

	fmt.Printf("Successfully left clipboard '%s'. To rejoin, run 'pcopy join %s'.\n", clipboard, pcopy.CollapseServerAddr(config.ServerAddr))
	return nil
}

func parseLeaveArgs(c *cli.Context) (string, string, *pcopy.Config) {
	configFileOverride := c.String("config")

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

	return configFile, clipboard, config
}
