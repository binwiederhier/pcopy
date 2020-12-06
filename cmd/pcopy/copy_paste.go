package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"pcopy"
	"regexp"
	"syscall"
)

func execCopy(args []string) {
	config, file := parseClientArgs("copy", args)
	client, err := pcopy.NewClient(config)
	if err != nil {
		fail(err)
	}

	if err := client.Copy(os.Stdin, file); err != nil {
		fail(err)
	}
}

func execPaste(args []string)  {
	config, fileId := parseClientArgs("paste", args)
	client, err := pcopy.NewClient(config)
	if err != nil {
		fail(err)
	}

	if err := client.Paste(os.Stdout, fileId); err != nil {
		fail(err)
	}
}

func parseClientArgs(command string, args []string) (*pcopy.Config, string) {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	flags.Usage = func() { showCopyPasteUsage(command, flags) }
	configFileOverride := flags.String("config", "", "Alternate config file (default is based on clipboard name)")
	certFile := flags.String("cert", "", "Certificate file to use for cert pinning")
	serverAddr := flags.String("server", "", "Server address")
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and file
	clipboard, file := parseClipboardAndFile(flags, *configFileOverride)

	// Load config
	configFile, config, err := pcopy.LoadConfig(*configFileOverride, clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile)
	}

	// Command line overrides
	if *serverAddr != "" {
		config.ServerAddr = pcopy.ExpandServerAddr(*serverAddr)
	}
	if *certFile != "" {
		config.CertFile = *certFile
	}
	if os.Getenv("PCOPY_KEY") != "" {
		config.Key, err = pcopy.DecodeKey(os.Getenv("PCOPY_KEY"))
		if err != nil {
			fail(err)
		}
	}

	return config, file
}

func parseClipboardAndFile(flags *flag.FlagSet, configFileOverride string) (string, string) {
	clipboard := pcopy.DefaultClipboard
	file := pcopy.DefaultFile
	if flags.NArg() > 0 {
		re := regexp.MustCompile(`^(?:([-_a-zA-Z0-9]+):)?([-_a-zA-Z0-9]*)$`)
		parts := re.FindStringSubmatch(flags.Arg(0))
		if len(parts) != 3 {
			fail(errors.New("invalid argument, must be in format [CLIPBOARD:]FILE"))
		}
		if parts[1] != "" {
			if configFileOverride != "" {
				fail(errors.New("invalid argument, -config cannot be set when clipboard is given"))
			}
			clipboard = parts[1]
		}
		if parts[2] != "" {
			file = parts[2]
		}
	}
	return clipboard, file
}

func showCopyPasteUsage(command string, flags *flag.FlagSet) {
	if command == "copy" {
		showCopyUsage(flags)
	} else {
		showPasteUsage(flags)
	}
}

func showCopyUsage(flags *flag.FlagSet) {
	fmt.Println("Usage: pcopy copy [OPTIONS..] [[CLIPBOARD:]FILE]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Read from STDIN and copy to remote clipboard. FILE is the remote file name, and")
	fmt.Println("  CLIPBOARD is the name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	fmt.Println("  /etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy copy < myfile.txt        # Copies myfile.txt to default clipboard & file")
	fmt.Println("  echo hi | pcopy copy work:     # Copies 'hi' to default file in clipboard 'work'")
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	fmt.Println()
	fmt.Println("To override or specify the remote server key, you may pass the PCOPY_KEY variable.")
	syscall.Exit(1)
}

func showPasteUsage(flags *flag.FlagSet) {
	fmt.Println("Usage: pcopy paste [OPTIONS..] [[CLIPBOARD:]FILE]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Write remote clipboard contents to STDOUT. FILE is the remote file name, and CLIPBOARD is")
	fmt.Println("  the name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	fmt.Println("  /etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy paste phil > phil.jpg    -- Reads file 'phil' from default clipboard to 'phil.jpg'")
	fmt.Println("  pcopy paste work:dog           -- Reads file 'dog' from 'work' clipboard and prints it")
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	fmt.Println()
	fmt.Println("To override or specify the remote server key, you may pass the PCOPY_KEY variable.")
	syscall.Exit(1)
}