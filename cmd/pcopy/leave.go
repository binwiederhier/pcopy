package main

import (
	"flag"
	"fmt"
	"heckel.io/pcopy"
	"os"
	"syscall"
)

func execLeave(args []string) {
	configFile, clipboard, config := parseLeaveArgs(args)

	if configFile == "" {
		fail(fmt.Errorf("clipboard '%s' does not exist", clipboard))
	}
	if err := os.Remove(configFile); err != nil {
		fail(err)
	}
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			if err := os.Remove(config.CertFile); err != nil {
				fail(err)
			}
		}
	}

	fmt.Printf("Successfully left clipboard '%s'. To rejoin, run 'pcopy join %s'.\n", clipboard, pcopy.CollapseServerAddr(config.ServerAddr))
}

func parseLeaveArgs(args []string) (string, string, *pcopy.Config) {
	flags := flag.NewFlagSet("pcopy leave", flag.ExitOnError)
	configFileOverride := flags.String("config", "", "Alternate config file (default is based on clipboard name)")
	flags.Usage = func() { showLeaveUsage(flags) }
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	// Parse clipboard and file
	clipboard := pcopy.DefaultClipboard
	if flags.NArg() > 0 {
		clipboard = flags.Arg(0)
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

	return configFile, clipboard, config
}

func showLeaveUsage(flags *flag.FlagSet) {
	eprintln("Usage: pcopy leave [OPTIONS..] [CLIPBOARD]")
	eprintln()
	eprintln("Description:")
	eprintln("  Removes the clipboard configuration and certificate (if any) from the config folder.")
	eprintln()
	eprintln("  The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or")
	eprintln("  /etc/pcopy/$CLIPBOARD.conf. If not config exists, it will fail.")
	eprintln()
	eprintln("Examples:")
	eprintln("  pcopy leave           # Leaves the default clipboard")
	eprintln("  pcopy leave work      # Leaves the clipboard called 'work'")
	eprintln()
	eprintln("Options:")
	flags.PrintDefaults()
	syscall.Exit(1)
}
