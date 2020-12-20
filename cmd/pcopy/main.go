package main

import (
	"flag"
	"fmt"
	"os"
)

// TODO print all error messages to STDERR
// TODO web ui, with drag and drop
// TODO TTL for "pcopy link" URLs
// TODO go1.16 with embed stuff
// TODO Let's Encrypt certs
// TODO max file size for total cache
// TODO max file size per file

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
		fmt.Printf("pcopy: %s\n", error)
	}

	fmt.Println("Usage: pcopy COMMAND [OPTION..] [ARG..]")
	fmt.Println()
	fmt.Println("Client-side commands:")
	fmt.Println("  copy      Read from STDIN/file(s) and copy to remote clipboard")
	fmt.Println("  paste     Write remote clipboard contents to STDOUT/file(s)")
	fmt.Println("  join      Join a remote clipboard")
	fmt.Println("  list      Lists all of the clipboards that have been joined")
	fmt.Println("  invite    Generate commands to invite others to join a clipboard")
	fmt.Println("  link      Generate direct download link to clipboard content")
	fmt.Println()
	fmt.Println("Server-side commands:")
	fmt.Println("  setup     Initial setup wizard for a new pcopy server")
	fmt.Println("  serve     Start pcopy server")
	fmt.Println("  keygen    Generate key for the server config")
	fmt.Println()
	fmt.Println("Try 'pcopy COMMAND -help' for more information.")
	fmt.Println()

	fmt.Printf("pcopy %s (%s), built at %s\n", version, commit[:7], date)
	fmt.Printf("Copyright (C) 2020 Philipp Heckel, distributed under the Apache License 2.0\n")
	os.Exit(1)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
