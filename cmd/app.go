// Package cmd provides the pcopy CLI application
package cmd

import (
	"github.com/urfave/cli/v2"
	"os"
)

const (
	categoryClient = "Client-side commands"
	categoryServer = "Server-side commands"
)

// New creates a new CLI application
func New() *cli.App {
	return &cli.App{
		Name:                   "pcopy",
		Usage:                  "copy/paste across machines",
		UsageText:              "pcopy COMMAND [OPTION..] [ARG..]",
		HideHelp:               true,
		HideVersion:            true,
		EnableBashCompletion:   true,
		UseShortOptionHandling: true,
		Reader:                 os.Stdin,
		Writer:                 os.Stdout,
		ErrWriter:              os.Stderr,
		Commands: []*cli.Command{
			// Client commands
			cmdCopy,
			cmdPaste,
			cmdJoin,
			cmdLeave,
			cmdList,
			cmdLink,

			// Server commands
			cmdServe,
			cmdSetup,
			cmdKeygen,
		},
	}
}

// Run runs the CLI application with the given arguments. The method handles the special
// case of converting "pcp" to "pcopy copy" and "ppaste" to "pcopy paste".
func Run(app *cli.App, args ...string) error {
	if args[0] == "pcp" {
		args = append([]string{"pcopy", "copy"}, args[1:]...)
	} else if args[0] == "ppaste" {
		args = append([]string{"pcopy", "paste"}, args[1:]...)
	}
	return app.Run(args)
}
