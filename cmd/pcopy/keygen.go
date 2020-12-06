package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"pcopy"
	"syscall"
)

func execKeygen(args []string) {
	flags := flag.NewFlagSet("keygen", flag.ExitOnError)
	flags.Usage = showKeygenUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	fmt.Print("Enter Password: ")
	password, err := terminal.ReadPassword(syscall.Stdin)
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
	fmt.Println("Usage: pcopy keygen")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Generate key for the server config. This command is interactive and will ask for a password.")
	fmt.Println()
	fmt.Println("  The output of the command can be pasted into the 'server.conf' file to secure a server, or")
	fmt.Println("  passed via the PCOPY_KEY environment variables to commands that support it.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy keygen    # Asks for password and generates key")
	syscall.Exit(1)
}
