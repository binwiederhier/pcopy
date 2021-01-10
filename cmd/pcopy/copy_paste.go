package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

var cmdCopy = &cli.Command{
	Name:        "copy",
	Usage:       "Read from STDIN/file(s) and copy to remote clipboard",
	UsageText:   "pcp [OPTIONS..] [[CLIPBOARD]:[ID]] [FILE..]",
	Action:      execCopy,
	Description: descriptionCopy,
	Category:    categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "alternate config file (default is based on clipboard name)"},
		&cli.StringFlag{Name: "server", Aliases: []string{"s"}, Usage: "server address"},
		&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Usage: "certificate file to use for cert pinning"},
		&cli.BoolFlag{Name: "quiet", Aliases: []string{"q"}, Usage: "do not output progress"},
	},
}

var cmdPaste = &cli.Command{
	Name:        "paste",
	Usage:       "Write remote clipboard contents to STDOUT/file(s)",
	UsageText:   "ppaste [OPTIONS..] [[CLIPBOARD]:[ID]] [DIR]",
	Action:      execPaste,
	Description: descriptionPaste,
	Category:    categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "alternate config file (default is based on clipboard name)"},
		&cli.StringFlag{Name: "server", Aliases: []string{"s"}, Usage: "server address"},
		&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Usage: "certificate file to use for cert pinning"},
		&cli.BoolFlag{Name: "quiet", Aliases: []string{"q"}, Usage: "do not output progress"},
	},
}

func execCopy(c *cli.Context) error {
	config, id, files := parseClientArgs(c)
	client, err := pcopy.NewClient(config)
	if err != nil {
		return err
	}

	if len(files) > 0 {
		if err := client.CopyFiles(files, id); err != nil {
			return err
		}
	} else {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return err
		}

		var reader io.ReadCloser
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			reader = os.Stdin
		} else {
			reader = createInteractiveReader()
		}

		if err := client.Copy(reader, id); err != nil {
			return err
		}
	}
	return nil
}

func createInteractiveReader() io.ReadCloser {
	eprintln("(Reading from STDIN, two empty lines will send)")
	eprintln()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) >= 2 && lines[len(lines)-1] == "" && lines[len(lines)-2] == "" {
			break
		}
	}
	content := strings.Join(lines[:len(lines)-1], "\n")
	return ioutil.NopCloser(strings.NewReader(content))
}

func execPaste(c *cli.Context) error {
	config, id, files := parseClientArgs(c)
	client, err := pcopy.NewClient(config)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		if err := client.PasteFiles(files[0], id); err != nil {
			return err
		}
	} else {
		if err := client.Paste(os.Stdout, id); err != nil {
			return err
		}
	}
	return nil
}

func parseClientArgs(c *cli.Context) (*pcopy.Config, string, []string) {
	configFileOverride := c.String("config")
	certFile := c.String("cert")
	serverAddr := c.String("server")
	quiet := c.Bool("quiet")

	// Parse clipboard, id and files
	clipboard, id, files := parseClipboardIDAndFiles(c.Args(), configFileOverride)

	// Load config
	configFile, config, err := pcopy.LoadConfig(configFileOverride, clipboard)
	if err != nil {
		fail(err)
	}

	// Load defaults
	if config.CertFile == "" {
		config.CertFile = pcopy.DefaultCertFile(configFile, true)
	}

	// Command line overrides
	if serverAddr != "" {
		config.ServerAddr = pcopy.ExpandServerAddr(serverAddr)
	}
	if certFile != "" {
		config.CertFile = certFile
	}
	if !quiet {
		config.ProgressFunc = progressOutput
	}
	if os.Getenv("PCOPY_KEY") != "" {
		config.Key, err = pcopy.DecodeKey(os.Getenv("PCOPY_KEY"))
		if err != nil {
			fail(err)
		}
	}

	return config, id, files
}

func parseClipboardIDAndFiles(args cli.Args, configFileOverride string) (string, string, []string) {
	clipboard := pcopy.DefaultClipboard
	id := pcopy.DefaultID
	files := make([]string, 0)
	if args.Len() > 0 {
		clipboard, id = parseClipboardAndID(args.Get(0), configFileOverride)
	}
	if args.Len() > 1 {
		files = args.Slice()[1:]
	}
	return clipboard, id, files
}

func parseClipboardAndID(clipboardAndID string, configFileOverride string) (string, string) {
	clipboard := pcopy.DefaultClipboard
	id := pcopy.DefaultID
	re := regexp.MustCompile(`^(?i)(?:([-_a-z0-9]*):)?(|[a-z0-9][-_.a-z0-9]*)$`)
	parts := re.FindStringSubmatch(clipboardAndID)
	if len(parts) != 3 {
		fail(errors.New("invalid argument, must be in format [CLIPBOARD:]ID"))
	}
	if parts[1] != "" {
		if configFileOverride != "" {
			fail(errors.New("invalid argument, -config cannot be set when clipboard is given"))
		}
		clipboard = parts[1]
	}
	if parts[2] != "" {
		id = parts[2]
	}
	return clipboard, id
}

var previousProgressLen int

func progressOutput(processed int64, total int64, done bool) {
	if done {
		if previousProgressLen > 0 {
			progress := fmt.Sprintf("%s (100%%)", pcopy.BytesToHuman(processed))
			progressWithSpaces := progress
			if len(progress) < previousProgressLen {
				progressWithSpaces += strings.Repeat(" ", previousProgressLen-len(progress))
			}
			eprintf("\r%s\r\n", progressWithSpaces)
		}
	} else {
		var progress string
		if total > 0 {
			progress = fmt.Sprintf("%s / %s (%.f%%)", pcopy.BytesToHuman(processed),
				pcopy.BytesToHuman(total), float64(processed)/float64(total)*100)
		} else {
			progress = pcopy.BytesToHuman(processed)
		}
		progressWithSpaces := progress
		if len(progress) < previousProgressLen {
			progressWithSpaces += strings.Repeat(" ", previousProgressLen-len(progress))
		}
		eprintf("\r%s", progressWithSpaces)
		previousProgressLen = len(progress)
	}
}

var descriptionCopy = `Without FILE arguments, this command reads STDIN and copies it to the remote clipboard. ID is
the remote file name, and CLIPBOARD is the name of the clipboard (both default to 'default').

If FILE arguments are passed, the command creates a ZIP archive of the passed files and copies
it to the remote clipboard.

The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or
/etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.

Examples:
  pcp < foo.txt            # Copies contents of foo.txt to the default clipboard
  pcp bar < bar.txt        # Copies contents of bar.txt to the default clipboard as 'bar'
  echo hi | pcp work:      # Copies 'hi' to the 'work' clipboard
  echo ho | pcp work:bla   # Copies 'ho' to the 'work' clipboard as 'bla'
  pcp : img1/ img2/        # Creates ZIP from two folders and copies it to the default clipboard

To override or specify the remote server key, you may pass the PCOPY_KEY variable.
`

var descriptionPaste = `Without DIR argument, this command write the remote clipboard contents to STDOUT. ID is the
remote file name, and CLIPBOARD is the name of the clipboard (both default to 'default').

If a DIR argument are passed, the command will assume the clipboard contents are a ZIP archive
and will extract its contents for DIR. If DIR does not exist, it will be created.

The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or
/etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.

Examples:
  ppaste                   # Reads from the default clipboard and prints its contents
  ppaste bar > bar.txt     # Reads 'bar' from the default clipboard to file 'bar.txt'
  ppaste work:             # Reads from the 'work' clipboard and prints its contents
  ppaste work:ho > ho.txt  # Reads 'ho' from the 'work' clipboard to file 'ho.txt'
  ppaste : images/         # Extracts ZIP from default clipboard to folder images/

To override or specify the remote server key, you may pass the PCOPY_KEY variable.
`
