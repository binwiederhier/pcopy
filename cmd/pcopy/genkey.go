package main

import (
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"pcopy"
	"syscall"
)

func execGenKey() {
	fmt.Print("Enter Password: ")
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Println()

	key, err := pcopy.GenKey(password)
	if err != nil {
		fail(err)
	}

	fmt.Printf("Success. Update your server config with:\nKey %s\n", key)
}
