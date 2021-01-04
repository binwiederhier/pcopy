package main

import (
	"flag"
	"fmt"
	"golang.org/x/term"
	"heckel.io/pcopy"
	"syscall"
)

func execKeygen(args []string) {
	flags := flag.NewFlagSet("pcopy keygen", flag.ExitOnError)
	flags.Usage = showKeygenUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	eprint("Enter Password: ")
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}

	key, err := pcopy.GenerateKey(password)
	if err != nil {
		fail(err)
	}

	fmt.Printf("\rKey %s\n", pcopy.EncodeKey(key))
}

func showKeygenUsage() {
	eprintln("Usage: pcopy keygen")
	eprintln()
	eprintln("Description:")
	eprintln("  Generate key for the server config. This command is interactive and will ask for a password.")
	eprintln()
	eprintln("  The output of the command can be pasted into the 'server.conf' file to secure a server, or")
	eprintln("  passed via the PCOPY_KEY environment variables to commands that support it.")
	eprintln()
	eprintln("Examples:")
	eprintln("  pcopy keygen    # Asks for password and generates key")
	syscall.Exit(1)
}
