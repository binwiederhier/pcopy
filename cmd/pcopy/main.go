package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"pcopy"
	"regexp"
)

const (
	systemConfigDir = "/etc/pcopy"
	systemCacheDir  = "/var/lib/pcopy"

	localConfigDir  = "$HOME/.config/pcopy"
	localCacheDir   = "$HOME/.cache/pcopy"
)

// pcopy join pcopy.heckel.io p
//  -> creates /etc/pcopy/p.conf

// pcopy join 10.0.160.123
//  -> creates /etc/pcopy/default.conf

// pcopy copy p: < bla.txt

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
	serverUrl := flags.String("server", "", "Server URL")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	clipId := "default"
	fileId := "default"
	if flags.NArg() > 0 {
		re := regexp.MustCompile(`^(?:([-_a-z0-9]+):)([-_a-z0-9]*)$`)
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
	if *serverUrl != "" {
		config.ServerUrl = *serverUrl
	}
	if config.ServerUrl == "" {
		fail(errors.New("server address missing, specify -server flag or add 'ServerUrl' to config"))
	}

	return config, fileId
}

func execServe()  {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	configName := flags.String("config", "server", "Alternate config name")
	listenAddr := flags.String("listen", "", "Listen address")
	cacheDir := flags.String("cache", "", "Cache dir")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}

	config, err := loadConfig(*configName)
	if err != nil {
		fail(err)
	}
	if *listenAddr != "" {
		config.ListenAddr = *listenAddr
	}
	if *cacheDir != "" {
		config.CacheDir = *cacheDir
	} else if config.CacheDir == "" {
		config.CacheDir, err = getCacheDir()
		if err != nil {
			fail(err)
		}
	}
	if config.ListenAddr == "" {
		fail(errors.New("listen address missing, specify -listen flag or add 'ListenAddr' to config"))
	}

	log.Printf("Using config %s, cache %s", *configName, config.CacheDir)
	log.Printf("Listening on %s", config.ListenAddr)
	if err := pcopy.Serve(config); err != nil {
		fail(err)
	}
}

func execJoin() {

}

func loadConfig(configName string) (*pcopy.Config, error) {
	var config *pcopy.Config
	localConfigFile := filepath.Join(os.ExpandEnv(localConfigDir), configName + ".conf")
	systemConfigFile := filepath.Join(systemConfigDir, configName + ".conf")

	if _, err := os.Stat(localConfigFile); err == nil {
		config, err = pcopy.LoadConfig(localConfigFile)
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

func getCacheDir() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	if u.Uid == "0" {
		return systemCacheDir, nil
	} else {
		return os.ExpandEnv(localCacheDir), nil
	}
}

func printSyntaxAndExit() {
	fmt.Println("Syntax:")
	fmt.Println("  pcopy serve [-listen :1986]")
	fmt.Println("    Start server")
	fmt.Println()
	fmt.Println("  pcopy copy [-config CONFIG] [-server http://...] < myfile.txt")
	fmt.Println("    Copy myfile.txt to the remote clipboard")
	fmt.Println()
	fmt.Println("  pcopy paste [-config CONFIG] [-server http://...] > myfile.txt")
	fmt.Println("    Paste myfile.txt from the remote clipboard")
	os.Exit(1)
}

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}