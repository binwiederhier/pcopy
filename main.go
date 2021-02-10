// pcopy is a temporary file host, nopaste and clipboard across machines. It can be used from the
// Web UI, via a CLI or without a client by using curl.
//
// Full documentation with examples and videos can be found at https://heckel.io/pcopy.
package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/cmd"
	"os"
	"runtime"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cli.AppHelpTemplate += fmt.Sprintf(`
Try 'pcopy COMMAND --help' for more information.

pcopy %s (%s), runtime %s, built at %s
Copyright (C) 2021 Philipp C. Heckel, distributed under the Apache License 2.0
`, version, commit[:7], runtime.Version(), date)

	app := cmd.New()
	app.Version = version

	if err := cmd.Run(app, os.Args...); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
