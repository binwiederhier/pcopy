package main

import (
	"errors"
	"flag"
	"fmt"
	"heckel.io/pcopy"
	"os"
	"regexp"
	"strings"
	"syscall"
)

func execCopy(cmd string, args []string) {
	config, id, files := parseClientArgs(cmd, args)
	client, err := pcopy.NewClient(config)
	if err != nil {
		fail(err)
	}

	if len(files) > 0 {
		if err := client.CopyFiles(files, id); err != nil {
			fail(err)
		}
	} else {
		if err := client.Copy(os.Stdin, id); err != nil {
			fail(err)
		}
	}
}

func execPaste(cmd string, args []string)  {
	config, id, files := parseClientArgs(cmd, args)
	client, err := pcopy.NewClient(config)
	if err != nil {
		fail(err)
	}

	if len(files) > 0 {
		if err := client.PasteFiles(files[0], id); err != nil {
			fail(err)
		}
	} else {
		if err := client.Paste(os.Stdout, id); err != nil {
			fail(err)
		}
	}
}

func parseClientArgs(command string, args []string) (*pcopy.Config, string, []string) {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	flags.Usage = func() { showCopyPasteUsage(flags) }
	configFileOverride := flags.String("config", "", "Alternate config file (default is based on clipboard name)")
	certFile := flags.String("cert", "", "Certificate file to use for cert pinning")
	serverAddr := flags.String("server", "", "Server address")
	quiet := flags.Bool("quiet", false, "Do not output progress")
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and id
	clipboard, id, files := parseClipboardAndId(flags, *configFileOverride)

	// Load config
	configFile, config, err := pcopy.LoadConfig(*configFileOverride, clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	// Command line overrides
	if *serverAddr != "" {
		config.ServerAddr = pcopy.ExpandServerAddr(*serverAddr)
	}
	if *certFile != "" {
		config.CertFile = *certFile
	}
	if !*quiet {
		config.ProgressFunc = progressOutput
	}
	if os.Getenv("PCOPY_KEY") != "" {
		config.Key, err = pcopy.DecodeKey(os.Getenv("PCOPY_KEY"))
		if err != nil {
			fail(err)
		}
	}

	return config, id, files
}

func parseClipboardAndId(flags *flag.FlagSet, configFileOverride string) (string, string, []string) {
	clipboard := pcopy.DefaultClipboard
	id := pcopy.DefaultId
	files := make([]string, 0)
	if flags.NArg() > 0 {
		re := regexp.MustCompile(`^(?:([-_a-zA-Z0-9]*):)?([-_a-zA-Z0-9]*)$`)
		parts := re.FindStringSubmatch(flags.Arg(0))
		if len(parts) != 3 {
			fail(errors.New("invalid argument, must be in format [[CLIPBOARD]:]ID"))
		}
		if parts[1] != "" {
			if configFileOverride != "" {
				fail(errors.New("invalid argument, -config cannot be set when clipboard is given"))
			}
			clipboard = parts[1]
		}
		if parts[2] != "" {
			id = parts[2]
		}
	}
	if flags.NArg() > 1 {
		files = flags.Args()[1:]
	}
	return clipboard, id, files
}

var previousProgressLen int
func progressOutput(processed int64, total int64) {
	if processed == -1 {
		fmt.Printf("\r%s\r", strings.Repeat(" ", previousProgressLen))
	} else {
		var progress string
		if total > 0 {
			progress = fmt.Sprintf("%s / %s (%.f%%)", pcopy.BytesToHuman(processed),
				pcopy.BytesToHuman(total), float64(processed)/float64(total)*100)
		} else {
			progress = pcopy.BytesToHuman(processed)
		}
		fmt.Printf("\r%s", progress)
		if len(progress) < previousProgressLen {
			fmt.Print(strings.Repeat(" ", previousProgressLen - len(progress)))
		}
		previousProgressLen = len(progress)
	}
}

func showCopyPasteUsage(flags *flag.FlagSet) {
	if flags.Name() == "pcopy copy" || flags.Name() == "pcp" {
		showCopyUsage(flags)
	} else {
		showPasteUsage(flags)
	}
}

func showCopyUsage(flags *flag.FlagSet) {
	fmt.Printf("Usage: %s [OPTIONS..] [[CLIPBOARD:]ID] [FILE..]\n", flags.Name())
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Without FILE arguments, this command reads STDIN and copies it to the remote clipboard. ID is")
	fmt.Println("  the remote file name, and CLIPBOARD is the name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("  If FILE arguments are passed, the command creates a ZIP archive of the passed files and copies")
	fmt.Println("  it to the remote clipboard.")
	fmt.Println()
	fmt.Println("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	fmt.Println("  /etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s < foo.txt            # Copies contents of foo.txt to the default clipboard\n", flags.Name())
	fmt.Printf("  %s bar < bar.txt        # Copies contents of bar.txt to the default clipboard as 'bar'\n", flags.Name())
	fmt.Printf("  echo hi | %s work:      # Copies 'hi' to the 'work' clipboard\n", flags.Name())
	fmt.Printf("  echo ho | %s work:bla   # Copies 'ho' to the 'work' clipboard as 'bla'\n", flags.Name())
	fmt.Printf("  %s : img1/ img2/        # Creates ZIP from two folders and copies it to the default clipboard\n", flags.Name())
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	fmt.Println()
	fmt.Println("To override or specify the remote server key, you may pass the PCOPY_KEY variable.")
	syscall.Exit(1)
}

func showPasteUsage(flags *flag.FlagSet) {
	fmt.Printf("Usage: %s [OPTIONS..] [[CLIPBOARD:]ID] [DIR]\n", flags.Name())
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Without DIR argument, this command write the remote clipboard contents to STDOUT. ID is the")
	fmt.Println("  remote file name, and CLIPBOARD is the name of the clipboard (both default to 'default').")
	fmt.Println()
	fmt.Println("  If a DIR argument are passed, the command will assume the clipboard contents are a ZIP archive")
	fmt.Println("  and will extract its contents for DIR. If DIR does not exist, it will be created.")
	fmt.Println()
	fmt.Println("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	fmt.Println("  /etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s                   # Reads from the default clipboard and prints its contents\n", flags.Name())
	fmt.Printf("  %s bar > bar.txt     # Reads 'bar' from the default clipboard to file 'bar.txt'\n", flags.Name())
	fmt.Printf("  %s work:             # Reads from the 'work' clipboard and prints its contents\n", flags.Name())
	fmt.Printf("  %s work:ho > ho.txt  # Reads 'ho' from the 'work' clipboard to file 'ho.txt'\n", flags.Name())
	fmt.Printf("  %s : images/         # Extracts ZIP from default clipboard to folder images/\n", flags.Name())
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	fmt.Println()
	fmt.Println("To override or specify the remote server key, you may pass the PCOPY_KEY variable.")
	syscall.Exit(1)
}