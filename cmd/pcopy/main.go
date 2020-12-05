package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Args[0] == "pcp" {
		execCopy(os.Args[1:])
	} else if os.Args[0] == "ppaste" {
		execPaste(os.Args[1:])
	} else {
		if len(os.Args) < 2 {
			usage()
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
		case "genkey":
			execGenKey()
		default:
			usage()
		}
	}
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  pcopy join SERVER [CLIP]")
	fmt.Println("    Join a remote clipboard. CLIP is the short alias that can be used to identify it. It")
	fmt.Println("    defaults to 'default'. This command is interactive and will write a config file")
	fmt.Println("    to ~/.config/pcopy (or /etc/pcopy). Example: pcopy join pcopy.example.com")
	fmt.Println()
	fmt.Println("  pcopy copy [-config CONFIG] [-server myhost.com] [[CLIP:]FILE]")
	fmt.Println("    Read from STDIN and copy to remote clipboard. FILE is the remote file name, and CLIP is")
	fmt.Println("    the alias name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("    Examples:")
	fmt.Println("      pcopy copy < myfile.txt        -- Copies myfile.txt to default clipboard & file")
	fmt.Println("      echo hi | pcopy copy work:     -- Copies 'hi' to default file in clipboard 'work'")
	fmt.Println()
	fmt.Println("  pcopy paste [-config CONFIG] [-server myhost.com] [[CLIP:]FILE]")
	fmt.Println("    Write remote clipboard contents to STDOUT. FILE is the remote file name, and CLIP is")
	fmt.Println("    the alias name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("    Examples:")
	fmt.Println("      pcopy paste phil > phil.jpg    -- Reads file 'phil' from default clipboard to 'phil.jpg'")
	fmt.Println("      pcopy paste work:dog           -- Reads file 'dog' from 'work' clipboard and prints it")
	fmt.Println()
	fmt.Println("  pcopy serve [-config CONFIG] [-listen ADDR:PORT] [-cache DIR] [-listen ADDR]")
	fmt.Println("    Start pcopy server and listen for incoming requests")
	fmt.Println()
	fmt.Println("  pcopy genkey")
	fmt.Println("    Generate key for the server config. This command is interactive.")
	os.Exit(1)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(2)
}