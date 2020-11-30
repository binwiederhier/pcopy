package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"pcopy"
	"regexp"
)

const (
	systemConfigDir = "/etc/pcopy"
	systemCacheDir  = "/var/cache/pcopy"

	userConfigDir = "$HOME/.config/pcopy"
	userCacheDir  = "$HOME/.cache/pcopy"
)

func main() {
	if len(os.Args) < 2 {
		printSyntaxAndExit()
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
	case "list":
		// TODO Implement list
	case "install":
		// TODO Implement install
	default:
		printSyntaxAndExit()
	}
}

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

func loadConfig(configName string) (*pcopy.Config, error) {
	var config *pcopy.Config
	userConfigFile := filepath.Join(os.ExpandEnv(userConfigDir), configName + ".conf")
	systemConfigFile := filepath.Join(systemConfigDir, configName + ".conf")

	if _, err := os.Stat(userConfigFile); err == nil {
		config, err = pcopy.LoadConfig(userConfigFile)
		if err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(systemConfigFile); err == nil {
		config, err = pcopy.LoadConfig(systemConfigFile)
		if err != nil {
			return nil, err
		}
	} else {
		config = pcopy.DefaultConfig
	}

	return config, nil
}


func getUserOrSystem(userValue string, systemValue string) string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}

	if u.Uid == "0" {
		return systemValue
	} else {
		return userValue
	}
}

func getDefaultCacheDir() string {
	return getUserOrSystem(os.ExpandEnv(userCacheDir), systemCacheDir)
}

func getConfigDir() string {
	return getUserOrSystem(os.ExpandEnv(userConfigDir), systemConfigDir)
}

func printSyntaxAndExit() {
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
	os.Exit(1)
}

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}