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
	cli.AppHelpTemplate += fmt.Sprintf(`
Try 'pcopy COMMAND -help' for more information.

pcopy %s (%s), runtime %s, built at %s
Copyright (C) 2020 Philipp C. Heckel, distributed under the Apache License 2.0
`, version, commit[:7], runtime.Version(), date)

	app := &cli.App{
		Name:                   "pcopy",
		Usage:                  "copy/paste across machines",
		UsageText:              "pcopy COMMAND [OPTION..] [ARG..]",
		Version:                version,
		HideHelp:               true,
		HideVersion:            true,
		EnableBashCompletion:   true,
		UseShortOptionHandling: true,
		//CustomAppHelpTemplate: helpTemplate(),
		// Compiled: time.Now(),
		Commands: []*cli.Command{
			// Client commands
			cmdCopy,
			cmdPaste,
			cmdJoin,
			cmdList,
			cmdLeave,
			cmdLink,
			cmdInvite,

			// Server commands
			cmdServe,
			cmdSetup,
			cmdKeygen,
		},
	}

	var args []string
	if os.Args[0] == "pcp" {
		args = append([]string{os.Args[0], "copy"}, os.Args[1:]...)
	} else if os.Args[0] == "ppaste" {
		args = append([]string{os.Args[0], "paste"}, os.Args[1:]...)
	} else {
		args = os.Args
	}
	if err := app.Run(args); err != nil {
		fail(err)
	}
}

func eprint(a ...interface{}) {
	if _, err := fmt.Fprint(os.Stderr, a...); err != nil {
		fail(err)
	}
}

func eprintln(a ...interface{}) {
	if _, err := fmt.Fprintln(os.Stderr, a...); err != nil {
		fail(err)
	}
}

func eprintf(format string, a ...interface{}) {
	if _, err := fmt.Fprintf(os.Stderr, format, a...); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
