package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	command := os.Args[1]
	switch command {
	case "copy":
		execCopy()
	case "paste":
		execPaste()
	case "serve":
		execServe()
	case "join":
		execJoin()
	case "genkey":
		execGenKey()
	case "list":
		// TODO Implement list
	case "install":
		// TODO Implement install
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Syntax:")
	fmt.Println("  pcopy serve [-listen :1986]")
	fmt.Println("    Start server")
	fmt.Println()
	fmt.Println("  pcopy copy [-server myhost.com] < myfile.txt")
	fmt.Println("    Copy myfile.txt to the remote clipboard")
	fmt.Println()
	fmt.Println("  pcopy paste [-server myhost.com] > myfile.txt")
	fmt.Println("    Paste myfile.txt from the remote clipboard")
	fmt.Println()
	fmt.Println("  pcopy join SERVER [ALIAS]")
	fmt.Println("    Join a clipboard as ALIAS")
	fmt.Println()
	fmt.Println("  pcopy genkey")
	fmt.Println("    Generate key for the server config")
	os.Exit(1)
}

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}