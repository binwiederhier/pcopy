package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
	"heckel.io/pcopy"
	"syscall"
)

var cmdKeygen = &cli.Command{
	Name:     "keygen",
	Usage:    "Generate key for the server config",
	Action:   execKeygen,
	Category: categoryServer,
	Description: `Generate key for the server config. This command is interactive and will ask for a password.

The output of the command can be pasted into the 'server.conf' file to secure a server, or
passed via the PCOPY_KEY environment variables to commands that support it.

Examples:
  pcopy keygen    # Asks for password and generates key
`,
}

func execKeygen(c *cli.Context) error {
	eprint("Enter Password: ")
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return err
	}

	key, err := pcopy.GenerateKey(password)
	if err != nil {
		return err
	}

	fmt.Printf("\rKey %s\n", pcopy.EncodeKey(key))
	return nil
}
