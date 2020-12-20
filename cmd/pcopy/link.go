package main

import (
	"flag"
	"fmt"
	"heckel.io/pcopy"
	"syscall"
)

func execLink(args []string)  {
	config, clipboard, id := parseLinkArgs(args)
	url, err := pcopy.GenerateUrl(config, id)
	if err != nil {
		fail(err)
	}

	fmt.Printf("# Temporary download link for file '%s' in clipboard '%s'\n", id, clipboard)
	if config.CertFile != "" {
		fmt.Println("# Warning: This clipboard uses a self-signed TLS certificate. Browsers will show a warning.")
		// TODO print cert fingerprint!
	}
	fmt.Println()
	fmt.Println(url)
	fmt.Println()
}

func parseLinkArgs(args []string) (*pcopy.Config, string, string) {
	flags := flag.NewFlagSet("pcopy link", flag.ExitOnError)
	configFileOverride := flags.String("config", "", "Alternate config file (default is based on clipboard name)")
	flags.Usage = func() { showLinkUsage(flags) }
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and file
	clipboard, id := pcopy.DefaultClipboard, pcopy.DefaultId
	if flags.NArg() > 0 {
		clipboard, id = parseClipboardAndId(flags.Arg(0), *configFileOverride)
	}

	// Load config
	configFile, config, err := pcopy.LoadConfig(*configFileOverride, clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	return config, clipboard, id
}

func showLinkUsage(flags *flag.FlagSet) {
	fmt.Println("Usage: pcopy link [OPTIONS..] [[CLIPBOARD]:[ID]]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Generates a link for the given clipboard file that can be used")
	fmt.Println("  to share with others.")
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	syscall.Exit(1)
}