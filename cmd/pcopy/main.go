package main

import (
	"flag"
	"fmt"
	"os"
)

// TODO print all error messages to STDERR

func main() {
	if os.Args[0] == "pcp" {
		execCopy(os.Args[1:])
	} else if os.Args[0] == "ppaste" {
		execPaste(os.Args[1:])
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
			execCopy(args)
		case "paste":
			execPaste(args)
		case "serve":
			execServe(args)
		case "join":
			execJoin(args)
		case "invite":
			execInvite(args)
		case "keygen":
			execKeygen(args)
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
	fmt.Println("Commands:")
	fmt.Println("  join      Join a remote clipboard")
	fmt.Println("  invite    Generate commands to invite others to join a clipboard")
	fmt.Println("  copy      Read from STDIN and copy to remote clipboard")
	fmt.Println("  paste     Write remote clipboard contents to STDOUT")
	fmt.Println("  serve     Start pcopy server")
	fmt.Println("  keygen    Generate key for the server config")
	fmt.Println()
	fmt.Println("Try 'pcopy COMMAND -help' for more information.")
	os.Exit(1)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
