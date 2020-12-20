package main

import (
	"flag"
	"fmt"
	"heckel.io/pcopy"
	"syscall"
	"time"
)

func execLink(args []string)  {
	config, clipboard, id, ttl := parseLinkArgs(args)
	url, err := pcopy.GenerateClipUrl(config, id, ttl)
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

func parseLinkArgs(args []string) (*pcopy.Config, string, string, time.Duration) {
	flags := flag.NewFlagSet("pcopy link", flag.ExitOnError)
	configFileOverride := flags.String("config", "", "Alternate config file (default is based on clipboard name)")
	ttl := flags.Duration("ttl", time.Hour * 6, "Defines the duration the link is valid for, only protected clipboards")
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

	return config, clipboard, id, *ttl
}

func showLinkUsage(flags *flag.FlagSet) {
	fmt.Println("Usage: pcopy link [OPTIONS..] [[CLIPBOARD]:[ID]]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Generates a link for the given clipboard file that can be used to share")
	fmt.Println("  with others.")
	fmt.Println()
	fmt.Println("  For password-protected clipboards, the link is temporary and only valid until")
	fmt.Println("  the time-to-live (--ttl) expires.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy link                 # Generates link for the default clipboard ")
	fmt.Println("  pcopy link -ttl 1h myfile  # Generates link 'myfile' in defalt clipboard that expires after 1h")
	fmt.Println("  pcopy link work:           # Generates link for default file in clipboard 'work'")
	fmt.Println()
	fmt.Println("Options:")
	flags.PrintDefaults()
	syscall.Exit(1)
}