package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"runtime"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

const (
	categoryClient = "Client-side commands"
	categoryServer = "Server-side commands"
)

func main() {
	if err := runApp(newApp(), os.Args...); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func newApp() *cli.App {
	cli.AppHelpTemplate += fmt.Sprintf(`
Try 'pcopy COMMAND --help' for more information.

pcopy %s (%s), runtime %s, built at %s
Copyright (C) 2021 Philipp C. Heckel, distributed under the Apache License 2.0
`, version, commit[:7], runtime.Version(), date)

	return &cli.App{
		Name:                   "pcopy",
		Usage:                  "copy/paste across machines",
		UsageText:              "pcopy COMMAND [OPTION..] [ARG..]",
		Version:                version,
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

func runApp(app *cli.App, args ...string) error {
	if args[0] == "pcp" {
		args = append([]string{"pcopy", "copy"}, args[1:]...)
	} else if args[0] == "ppaste" {
		args = append([]string{"pcopy", "paste"}, args[1:]...)
	}
	return app.Run(args)
}
