package main

import (
	"errors"
	"flag"
	"os"
	"pcopy"
	"regexp"
)

func execCopy() {
	config, fileId := parseClientArgs("copy")
	client := pcopy.NewClient(config)

	if err := client.Copy(os.Stdin, fileId); err != nil {
		fail(err)
	}
}

func execPaste()  {
	config, fileId := parseClientArgs("paste")
	client := pcopy.NewClient(config)

	if err := client.Paste(os.Stdout, fileId); err != nil {
		fail(err)
	}
}

func parseClientArgs(command string) (*pcopy.Config, string) {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	// configFile := flags.String("config", "", "Alternate config file")
	serverAddr := flags.String("server", "", "Server address")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	// Parse alias and file
	alias := "default"
	fileId := "default"
	if flags.NArg() > 0 {
		re := regexp.MustCompile(`^(?:([-_a-zA-Z0-9]+):)?([-_a-zA-Z0-9]*)$`)
		parts := re.FindStringSubmatch(flags.Arg(0))
		if len(parts) != 3 {
			fail(errors.New("invalid argument, must be in format [ALIAS:]FILEID"))
		}
		if parts[1] != "" {
			alias = parts[1]
		}
		if parts[2] != "" {
			fileId = parts[2]
		}
	}

	// Load config
	var err error
	config := pcopy.DefaultConfig
	configFile := pcopy.FindConfigFile(alias)
	if configFile != "" {
		config, err = pcopy.LoadConfig(configFile)
		if err != nil {
			fail(err)
		}
	}

	// Command line overrides
	if *serverAddr != "" {
		config.ServerAddr = *serverAddr
	}
	// FIXME add -key parsing

	// Validate
	if config.ServerAddr == "" {
		fail(errors.New("server address missing, specify -server flag or add 'ServerAddr' to config"))
	}
	if config.Key == nil {
		fail(errors.New("key missing, specify -key flag or add 'Key' to config"))
	}

	return config, fileId
}
