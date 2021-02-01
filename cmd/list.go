package cmd

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/util"
	"math"
	"strings"
)

var cmdList = &cli.Command{
	Name:        "list",
	Aliases:     []string{"l"},
	Usage:       "Lists all of the clipboards that have been joined",
	Action:      execList,
	Category:    categoryClient,
	Description: "Lists all of the clipboards that have been joined.",
}

func execList(c *cli.Context) error {
	store := config.NewStore()
	configs := store.All()
	if len(configs) > 0 {
		clipboardHeader := "Clipboard"
		clipboardMaxLen := len(clipboardHeader)
		serverAddrHeader := "Server address"
		serverAddrMaxLen := len(serverAddrHeader)
		configFileHeader := "Config file"
		configFileMaxLen := len(configFileHeader)
		for filename, conf := range configs {
			clipboard := config.ExtractClipboard(filename)
			shortName := util.CollapseHome(filename)
			serverAddr := config.CollapseServerAddr(conf.ServerAddr)
			clipboardMaxLen = int(math.Max(float64(clipboardMaxLen), float64(len(clipboard))))
			serverAddrMaxLen = int(math.Max(float64(serverAddrMaxLen), float64(len(serverAddr))))
			configFileMaxLen = int(math.Max(float64(configFileMaxLen), float64(len(shortName))))
		}

		lineFmt := fmt.Sprintf("%%-%ds %%-%ds %%s\n", clipboardMaxLen, serverAddrMaxLen)
		fmt.Fprintf(c.App.ErrWriter, lineFmt, clipboardHeader, serverAddrHeader, "Config file")
		fmt.Fprintf(c.App.ErrWriter, lineFmt, strings.Repeat("-", clipboardMaxLen), strings.Repeat("-", serverAddrMaxLen), strings.Repeat("-", configFileMaxLen))
		for filename, conf := range configs {
			clipboard := config.ExtractClipboard(filename)
			shortName := util.CollapseHome(filename)
			serverAddr := config.CollapseServerAddr(conf.ServerAddr)
			fmt.Fprintf(c.App.ErrWriter, lineFmt, clipboard, serverAddr, shortName)
		}
	} else {
		fmt.Fprintln(c.App.ErrWriter, "No clipboards found. You can use 'pcopy join' to connect to existing clipboards.")
	}
	return nil
}
