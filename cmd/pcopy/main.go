package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if os.Args[0] == "pcp" {
		execCopy("pcp", os.Args[1:])
	} else if os.Args[0] == "ppaste" {
		execPaste("ppaste", os.Args[1:])
	} else {
		flag.Usage = showUsage
		flag.Parse()

		if len(os.Args) < 2 {
			showUsage()
		}

		command := os.Args[1]
		args := os.Args[2:]

		switch command {
		case "copy":
			execCopy("pcopy copy", args)
		case "paste":
			execPaste("pcopy paste", args)
		case "serve":
			execServe(args)
		case "join":
			execJoin(args)
		case "invite":
			execInvite(args)
		case "keygen":
			execKeygen(args)
		case "setup":
			execSetup(args)
		case "list":
			execList(args)
		case "link":
			execLink(args)
		default:
			showUsageWithError(fmt.Sprintf("invalid command: %s", command))
		}
	}
}

func showUsage() {
	showUsageWithError("")
}

func showUsageWithError(error string) {
	if error != "" {
		eprintf("pcopy: %s\n", error)
	}

	eprintln("Usage: pcopy COMMAND [OPTION..] [ARG..]")
	eprintln()
	eprintln("Client-side commands:")
	eprintln("  copy      Read from STDIN/file(s) and copy to remote clipboard")
	eprintln("  paste     Write remote clipboard contents to STDOUT/file(s)")
	eprintln("  join      Join a remote clipboard")
	eprintln("  list      Lists all of the clipboards that have been joined")
	eprintln("  invite    Generate commands to invite others to join a clipboard")
	eprintln("  link      Generate direct download link to clipboard content")
	eprintln()
	eprintln("Server-side commands:")
	eprintln("  setup     Initial setup wizard for a new pcopy server")
	eprintln("  serve     Start pcopy server")
	eprintln("  keygen    Generate key for the server config")
	eprintln()
	eprintln("Try 'pcopy COMMAND -help' for more information.")
	eprintln()
	eprintf("pcopy %s (%s, runtime %s), built at %s\n", version, commit[:7], runtime.Version(), date)
	eprintf("Copyright (C) 2020 Philipp C. Heckel, distributed under the Apache License 2.0\n")
	os.Exit(1)
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
