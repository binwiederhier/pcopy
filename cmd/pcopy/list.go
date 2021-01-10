package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"math"
	"strings"
)

var cmdList = &cli.Command{
	Name:        "list",
	Usage:       "Lists all of the clipboards that have been joined",
	Action:      execList,
	Category:    categoryClient,
	Description: "Lists all of the clipboards that have been joined.",
}

func execList(c *cli.Context) error {
	configs := pcopy.ListConfigs()
	if len(configs) > 0 {
		clipboardHeader := "Clipboard"
		clipboardMaxLen := len(clipboardHeader)
		serverAddrHeader := "Server address"
		serverAddrMaxLen := len(serverAddrHeader)
		configFileHeader := "Config file"
		configFileMaxLen := len(configFileHeader)
		for filename, config := range pcopy.ListConfigs() {
			clipboard := pcopy.ExtractClipboard(filename)
			shortName := pcopy.CollapseHome(filename)
			serverAddr := pcopy.CollapseServerAddr(config.ServerAddr)
			clipboardMaxLen = int(math.Max(float64(clipboardMaxLen), float64(len(clipboard))))
			serverAddrMaxLen = int(math.Max(float64(serverAddrMaxLen), float64(len(serverAddr))))
			configFileMaxLen = int(math.Max(float64(configFileMaxLen), float64(len(shortName))))
		}

		lineFmt := fmt.Sprintf("%%-%ds %%-%ds %%s\n", clipboardMaxLen, serverAddrMaxLen)
		fmt.Printf(lineFmt, clipboardHeader, serverAddrHeader, "Config file")
		fmt.Printf(lineFmt, strings.Repeat("-", clipboardMaxLen), strings.Repeat("-", serverAddrMaxLen), strings.Repeat("-", configFileMaxLen))
		for filename, config := range pcopy.ListConfigs() {
			clipboard := pcopy.ExtractClipboard(filename)
			shortName := pcopy.CollapseHome(filename)
			serverAddr := pcopy.CollapseServerAddr(config.ServerAddr)
			fmt.Printf(lineFmt, clipboard, serverAddr, shortName)
		}
	} else {
		fmt.Println("No clipboards found. You can use 'pcopy join' to connect to existing clipboards.")
	}
	return nil
}
