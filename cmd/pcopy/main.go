package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"pcopy"
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
	case "genkey":
		execGenKey()
	case "list":
		// TODO Implement list
	case "install":
		// TODO Implement install
	default:
		printSyntaxAndExit()
	}
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
	fmt.Println()
	fmt.Println("  pcopy genkey")
	fmt.Println("    Generate key for the server config")
	os.Exit(1)
}

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}