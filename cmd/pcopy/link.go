package main

import (
	"flag"
	"fmt"
	"heckel.io/pcopy"
	"syscall"
	"time"
)

func execLink(args []string) {
	config, clipboard, id, ttl := parseLinkArgs(args)
	url, err := pcopy.GenerateClipURL(config, id, ttl)
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
	ttl := flags.Duration("ttl", time.Hour*6, "Defines the duration the link is valid for, only protected clipboards")
	flags.Usage = func() { showLinkUsage(flags) }
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and file
	clipboard, id := pcopy.DefaultClipboard, pcopy.DefaultID
	if flags.NArg() > 0 {
		clipboard, id = parseClipboardAndID(flags.Arg(0), *configFileOverride)
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
	eprintln("Usage: pcopy link [OPTIONS..] [[CLIPBOARD]:[ID]]")
	eprintln()
	eprintln("Description:")
	eprintln("  Generates a link for the given clipboard file that can be used to share")
	eprintln("  with others.")
	eprintln()
	eprintln("  For password-protected clipboards, the link is temporary and only valid until")
	eprintln("  the time-to-live (--ttl) expires.")
	eprintln()
	eprintln("Examples:")
	eprintln("  pcopy link                 # Generates link for the default clipboard ")
	eprintln("  pcopy link -ttl 1h myfile  # Generates link 'myfile' in defalt clipboard that expires after 1h")
	eprintln("  pcopy link work:           # Generates link for default file in clipboard 'work'")
	eprintln()
	eprintln("Options:")
	flags.PrintDefaults()
	syscall.Exit(1)
}
