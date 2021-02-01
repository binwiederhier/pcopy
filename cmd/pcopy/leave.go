package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/config"
	"os"
)

var cmdLeave = &cli.Command{
	Name:      "leave",
	Aliases:   []string{"rm"},
	Usage:     "Leave a remote clipboard",
	UsageText: "pcopy leave [OPTIONS..] [CLIPBOARD]",
	Action:    execLeave,
	Category:  categoryClient,
	Description: `Removes the clipboard configuration and certificate/key (if any) from the config folder.

The command will find a clipboard config in ~/.config/pcopy/$CLIPBOARD.conf or
/etc/pcopy/$CLIPBOARD.conf. If no config exists, it will fail.

Examples:
  pcopy leave           # Leaves the default clipboard
  pcopy leave work      # Leaves the clipboard called 'work'`,
}

func execLeave(c *cli.Context) error {
	// Parse clipboard and file
	clipboard := config.DefaultClipboard
	if c.NArg() > 0 {
		clipboard = c.Args().First()
	}
	store := config.NewStore()
	filename := store.FileFromName(clipboard)
	if _, err := os.Stat(filename); err != nil {
		return fmt.Errorf("clipboard '%s' does not exist", clipboard)
	}
	conf, err := config.LoadFromFile(filename)
	if err != nil {
		return fmt.Errorf("cannot load config for %s: %w", clipboard, err)
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	if conf.CertFile != "" {
		if _, err := os.Stat(conf.CertFile); err == nil {
			if err := os.Remove(conf.CertFile); err != nil {
				return err
			}
		}
	}
	if conf.KeyFile != "" {
		// This is odd, but we may want to "leave" a server, which has a key file
		if _, err := os.Stat(conf.KeyFile); err == nil {
			if err := os.Remove(conf.KeyFile); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(c.App.Writer, "Successfully left clipboard '%s'. To rejoin, run 'pcopy join %s'.\n", clipboard, config.CollapseServerAddr(conf.ServerAddr))
	return nil
}
