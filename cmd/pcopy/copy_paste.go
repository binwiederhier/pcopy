package main

import (
	"errors"
	"flag"
	"os"
	"pcopy"
	"regexp"
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
	configFileOverride := flags.String("config", "", "Alternate config file")
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
		config.ServerAddr = *serverAddr
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
