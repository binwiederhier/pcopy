package cmd

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
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
  pcopy keygen    # Asks for password and generates key`,
}

func execKeygen(c *cli.Context) error {
	fmt.Fprint(c.App.ErrWriter, "Enter Password: ")
	password, err := util.ReadPassword(c.App.Reader)
	if err != nil {
		return err
	}

	key, err := crypto.GenerateKey(password)
	if err != nil {
		return err
	}

	fmt.Fprintf(c.App.Writer, "\rKey %s\n", crypto.EncodeKey(key))
	return nil
}
