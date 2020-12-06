package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if os.Args[0] == "pcp" {
		execCopy(os.Args[1:])
	} else if os.Args[0] == "ppaste" {
		execPaste(os.Args[1:])
	} else {
		help := flag.Bool("help", false, "Show help")
		flag.Usage = showUsage
		flag.Parse()

		if *help {
			showHelp()
		}

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
			execKeygen()
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
	fmt.Println("Try 'pcopy -help' for more information.")
	os.Exit(1)
}

func showHelp() {
	fmt.Println("Usage:")
	fmt.Println("  pcopy join SERVER [CLIPBOARD]")
	fmt.Println("    Join a remote clipboard. CLIPBOARD is the short alias that can be used to identify it. It")
	fmt.Println("    defaults to 'default'. This command is interactive and will write a config file")
	fmt.Println("    to ~/.config/pcopy (or /etc/pcopy). Example: pcopy join pcopy.example.com")
	fmt.Println()
	fmt.Println("  pcopy invite CLIPBOARD")
	fmt.Println("    Generate commands that can be shared with others so they can easily join this clipboard")
	fmt.Println()
	fmt.Println("  pcopy copy [-config CONFIG] [-server myhost.com] [[CLIPBOARD:]FILE]")
	fmt.Println("    Read from STDIN and copy to remote clipboard. FILE is the remote file name, and CLIPBOARD is")
	fmt.Println("    the alias name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("    Examples:")
	fmt.Println("      pcopy copy < myfile.txt        -- Copies myfile.txt to default clipboard & file")
	fmt.Println("      echo hi | pcopy copy work:     -- Copies 'hi' to default file in clipboard 'work'")
	fmt.Println()
	fmt.Println("  pcopy paste [-config CONFIG] [-server myhost.com] [[CLIPBOARD:]FILE]")
	fmt.Println("    Write remote clipboard contents to STDOUT. FILE is the remote file name, and CLIPBOARD is")
	fmt.Println("    the alias name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("    Examples:")
	fmt.Println("      pcopy paste phil > phil.jpg    -- Reads file 'phil' from default clipboard to 'phil.jpg'")
	fmt.Println("      pcopy paste work:dog           -- Reads file 'dog' from 'work' clipboard and prints it")
	fmt.Println()
	fmt.Println("  pcopy serve [-config CONFIG] [-listen ADDR:PORT] [-cache DIR] [-listen ADDR]")
	fmt.Println("    Start pcopy server and listen for incoming requests")
	fmt.Println()
	fmt.Println("  pcopy keygen")
	fmt.Println("    Generate key for the server config. This command is interactive.")
	os.Exit(1)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}