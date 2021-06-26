package cmd

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
	"strings"
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

	fmt.Fprintf(c.App.ErrWriter, "\r%s\rConfirm: ", strings.Repeat(" ", 25))
	confirm, err := util.ReadPassword(c.App.Reader)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(confirm, password) != 1 {
		return errors.New("passwords do not match: try it again, but this time type slooowwwlly")
	}

	key, err := crypto.GenerateKey(password)
	if err != nil {
		return err
	}

	fmt.Fprintf(c.App.Writer, "\rKey %s\n", crypto.EncodeKey(key))
	return nil
}
