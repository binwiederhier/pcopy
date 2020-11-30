package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
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
	serverAddr := flags.String("server", "", "Server address")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	clipId := "default"
	fileId := "default"
	if flags.NArg() > 0 {
		re := regexp.MustCompile(`^(?:([-_a-zA-Z0-9]+):)?([-_a-zA-Z0-9]*)$`)
		parts := re.FindStringSubmatch(flags.Arg(0))
		if len(parts) != 3 {
			fail(errors.New("invalid clip ID, must be in format [CLIPID:]FILEID"))
		}
		if parts[1] != "" {
			clipId = parts[1]
		}
		if parts[2] != "" {
			fileId = parts[2]
		}
	}

	config, err := loadConfig(clipId)
	if err != nil {
		fail(err)
	}
	if *serverAddr != "" {
		config.ServerAddr = *serverAddr
	}
	if config.ServerAddr == "" {
		fail(errors.New("server address missing, specify -server flag or add 'ServerAddr' to config"))
	}
	if config.CertFile == "" {
		config.CertFile = filepath.Join(getConfigDir(), clipId + ".crt")
		if _, err := os.Stat(config.CertFile); err != nil {
			fail(errors.New("cert file missing, add 'CertFile' to config"))
		}
	}

	return config, fileId
}
