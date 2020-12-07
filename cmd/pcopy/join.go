package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"heckel.io/pcopy"
	"syscall"
)

func execJoin(args []string) {
	flags := flag.NewFlagSet("join", flag.ExitOnError)
	flags.Usage = func() { showJoinUsage(flags) }
	force := flags.Bool("force", false, "Overwrite config if it already exists")
	auto := flags.Bool("auto", false, "Automatically choose clipboard alias")
	if err := flags.Parse(args); err != nil {
		fail(err)
	}
	if flags.NArg() < 1 {
		fail(errors.New("missing server address, see -help for usage details"))
	}
	if *force && *auto {
		fail(errors.New("cannot use -auto and -force"))
	}

	clipboard := pcopy.DefaultClipboard
	serverAddr := pcopy.ExpandServerAddr(flags.Arg(0))
	if flags.NArg() > 1 {
		clipboard = flags.Arg(1)
	}

	// Find config file
	var configFile string
	if *auto {
		clipboard, configFile = pcopy.FindNewConfigFile(clipboard)
	} else {
		configFile = pcopy.FindConfigFile(clipboard)
		if configFile != "" && !*force {
			fail(errors.New(fmt.Sprintf("config file %s exists, you may want to specify a different clipboard name, or use -force to override", configFile)))
		}
		configFile = pcopy.GetConfigFileForClipboard(clipboard)
	}

	// Read basic info from server
	client, err := pcopy.NewClient(&pcopy.Config{
		ServerAddr: serverAddr,
	})
	if err != nil {
		fail(err)
	}

	info, err := client.Info()
	if err != nil {
		fail(err)
	}

	// Override server address if set (server advertised a specific address)
	if info.ServerAddr != "" {
		serverAddr = pcopy.ExpandServerAddr(info.ServerAddr)
	}

	// Read and verify that password was correct (if server is secured with key)
	var key *pcopy.Key

	if info.Salt != nil {
		envKey := os.Getenv("PCOPY_KEY") // TODO document this
		if envKey != "" {
			key, err = pcopy.DecodeKey(envKey)
			if err != nil {
				fail(err)
			}
		} else {
			password := readPassword()
			key = pcopy.DeriveKey(password, info.Salt)
			err = client.Verify(info.Certs, key)
			if err != nil {
				fail(errors.New(fmt.Sprintf("Failed to join clipboard, %s", err.Error())))
			}
		}
	}

	// Write config file
	config := &pcopy.Config{
		ServerAddr: serverAddr,
		Key: key, // May be nil, but that's ok
	}
	if err := config.WriteFile(configFile); err != nil {
		fail(err)
	}

	// Write self-signed certs (only if Verify didn't work with secure client)
	if info.Certs != nil {
		certFile := pcopy.DefaultCertFile(configFile, false)
		certsEncoded, err := pcopy.EncodeCerts(info.Certs)
		if err != nil {
			fail(err)
		}
		if err := ioutil.WriteFile(certFile, certsEncoded, 0644); err != nil {
			fail(err)
		}
	}

	printInstructions(configFile, clipboard, info)
}

func readPassword() []byte {
	fmt.Print("Enter password to join clipboard: ")
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Print("\r")
	return password
}

func printInstructions(configFile string, clipboard string, info *pcopy.Info) {
	clipboardPrefix := ""
	if clipboard != pcopy.DefaultClipboard {
		clipboardPrefix = fmt.Sprintf(" %s:", clipboard)
	}

	if clipboard == pcopy.DefaultClipboard {
		fmt.Printf("Successfully joined clipboard, config written to %s\n", configFile)
	} else {
		fmt.Printf("Successfully joined clipboard as alias '%s', config written to %s\n", clipboard, configFile)
	}

	if info.Certs != nil {
		fmt.Println()
		fmt.Println("Warning: The TLS certificate was self-signed and has been pinned.")
		fmt.Println("Future communication will be secure, but joining could have been intercepted.")
	}

	fmt.Println()
	if _, err := os.Stat("/usr/bin/pcp"); err == nil {
		fmt.Printf("You may now use 'pcp%s' and 'ppaste%s'. See 'pcopy -h' for usage details.\n", clipboardPrefix, clipboardPrefix)
	} else {
		fmt.Printf("You may now use 'pcopy copy%s' and 'pcopy paste%s'. See 'pcopy -h' for usage details.\n", clipboardPrefix, clipboardPrefix)
	}
	fmt.Println("To install pcopy on other computers, or join this clipboard, use 'pcopy invite' command.")
}

func showJoinUsage(flags *flag.FlagSet) {
	fmt.Println("Usage: pcopy join [OPTIONS..] SERVER [CLIPBOARD]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Connects to a remote clipboard with the server address SERVER. CLIPBOARD is the local alias")
	fmt.Println("  that can be used to identify it (default is 'default'). This command is interactive and")
	fmt.Println("  will write a config file to ~/.config/pcopy/$CLIPBOARD.conf (or /etc/pcopy/$CLIPBOARD.conf).")
	fmt.Println()
	fmt.Println("  The command will ask for a password if the remote clipboard requires one, unless the PCOPY_KEY")
	fmt.Println("  environment variable is passed.")
	fmt.Println()
	fmt.Println("  If the remote server's certificate is self-signed, its certificate will be downloaded to ")
	fmt.Println("  ~/.config/pcopy/$CLIPBOARD.crt (or /etc/pcopy/$CLIPBOARD.crt) and pinned for future connections.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy join pcopy.example.com     # Joins remote clipboard as local alias 'default'")
	fmt.Println("  pcopy join pcopy.work.com work   # Joins remote clipboard with local alias 'work'")
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	syscall.Exit(1)
}