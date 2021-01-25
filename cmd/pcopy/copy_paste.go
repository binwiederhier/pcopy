package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy"
	"io"
	"os"
	"regexp"
	"strings"
)

var cmdCopy = &cli.Command{
	Name:    "copy",
	Aliases: []string{"c"},
	Usage:   "Read from STDIN/file(s) and copy to remote clipboard",
	UsageText: `pcopy copy [OPTIONS..] [[CLIPBOARD]:[ID]] [FILE..]
   pcp [OPTIONS..] [[CLIPBOARD]:[ID]] [FILE..]`,
	Action:   execCopy,
	Category: categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "load config file from `FILE`"},
		&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Usage: "load certificate file `CERT` to use for cert pinning"},
		&cli.StringFlag{Name: "server", Aliases: []string{"S"}, Usage: "connect to server `ADDR[:PORT]` (default port: 2586)"},
		&cli.BoolFlag{Name: "quiet", Aliases: []string{"q"}, Usage: "do not output progress"},
		&cli.BoolFlag{Name: "nolink", Aliases: []string{"n"}, Usage: "do not show link and curl command after copying"},
		&cli.BoolFlag{Name: "stream", Aliases: []string{"s"}, Usage: "stream data to other client via fifo device"},
		&cli.BoolFlag{Name: "random", Aliases: []string{"r"}, Usage: "pick random file name and ignore name that has been passed"},
		&cli.BoolFlag{Name: "read-only", Aliases: []string{"ro"}, Usage: "make remote file read-only (if supported by the server)"},
		&cli.BoolFlag{Name: "read-write", Aliases: []string{"rw"}, Usage: "allow file to be overwritten (if supported by the server)"},
		&cli.DurationFlag{Name: "ttl", Aliases: []string{"t"}, DefaultText: "server default", Usage: "set duration the link is valid for to `TTL`"},
	},
	Description: `Without FILE arguments, this command reads STDIN and copies it to the remote clipboard. ID is
the remote file name, and CLIPBOARD is the name of the clipboard (both default to 'default').

If FILE arguments are passed, the command creates a ZIP archive of the passed files and copies
it to the remote clipboard.

The command will load a the clipboard config from ~/.config/pcopy/$CLIPBOARD.conf or
/etc/pcopy/$CLIPBOARD.conf. Config options can be overridden using the command line options.

Examples:
  pcp < foo.txt            # Copies contents of foo.txt to the default clipboard
  pcp bar < bar.txt        # Copies contents of bar.txt to the default clipboard as 'bar'
  echo hi | pcp -l work:   # Copies 'hi' to the 'work' clipboard and print links
  echo ho | pcp work:bla   # Copies 'ho' to the 'work' clipboard as 'bla'
  pcp : img1/ img2/        # Creates ZIP from two folders and copies it to the default clipboard
  yes | pcp --stream       # Stream contents to the other end via FIFO device

To override or specify the remote server key, you may pass the PCOPY_KEY variable.`,
}

var cmdPaste = &cli.Command{
	Name:    "paste",
	Aliases: []string{"p"},
	Usage:   "Write remote clipboard contents to STDOUT/file(s)",
	UsageText: `pcopy paste [OPTIONS..] [[CLIPBOARD]:[ID]] [DIR]
   ppaste [OPTIONS..] [[CLIPBOARD]:[ID]] [DIR]`,
	Action:   execPaste,
	Category: categoryClient,
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "load config file from `FILE`"},
		&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Usage: "load certificate file `CERT` to use for cert pinning"},
		&cli.StringFlag{Name: "server", Aliases: []string{"S"}, Usage: "connect to server `ADDR[:PORT]` (default port: 2586)"},
		&cli.BoolFlag{Name: "quiet", Aliases: []string{"q"}, Usage: "do not output progress"},
	},
	Description: `Without DIR argument, this command write the remote clipboard contents to STDOUT. ID is the
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

To override or specify the remote server key, you may pass the PCOPY_KEY variable.`,
}

func execCopy(c *cli.Context) error {
	config, id, files, err := parseClientArgs(c)
	if err != nil {
		return err
	}
	client, err := pcopy.NewClient(config)
	if err != nil {
		return err
	}

	stream := c.Bool("stream")
	link := !c.Bool("nolink")
	ttl := c.Duration("ttl")
	random := c.Bool("random")
	readonly := c.Bool("read-only")
	readwrite := c.Bool("read-write")

	if readonly && readwrite {
		return cli.Exit("error: either --read-only or --read-write are allowed, not both", 1)
	}
	fileMode := ""
	if readonly {
		fileMode = pcopy.FileModeReadOnly
	} else if readwrite {
		fileMode = pcopy.FileModeReadWrite
	}

	if random {
		id = ""
	}

	var fileInfo *pcopy.FileInfo
	if stream {
		fileInfo, err = client.Reserve(id)
		if err != nil {
			return err
		}
		id = fileInfo.File
	}

	if link && stream {
		fmt.Fprint(c.App.ErrWriter, pcopy.FileInfoInstructions(fileInfo))
		fmt.Fprintln(c.App.ErrWriter)
		fmt.Fprintln(c.App.ErrWriter, "# Streaming contents: upload will hold until you start downloading using any of the commands above.")
	}

	if len(files) > 0 {
		fileInfo, err = client.CopyFiles(files, id, ttl, fileMode, stream)
		if err != nil {
			return handleCopyError(c.App.ErrWriter, err)
		}
	} else {
		stat, err := c.App.Reader.(*os.File).Stat()
		if err != nil {
			return err
		}

		var reader io.ReadCloser
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			reader, _ = c.App.Reader.(*os.File)
		} else {
			reader = createInteractiveReader(c.App.Reader, c.App.ErrWriter)
		}

		fileInfo, err = client.Copy(reader, id, ttl, fileMode, stream)
		if err != nil {
			return handleCopyError(c.App.ErrWriter, err)
		}
	}

	if link && !stream {
		fmt.Fprintf(c.App.ErrWriter, pcopy.FileInfoInstructions(fileInfo))
	}
	return nil
}

func handleCopyError(errWriter io.Writer, err error) error {
	if err == pcopy.ErrHTTPPartialContent {
		eprintln(" (interrupted by client)")
		return nil // This is not really an error!
	}
	if err == pcopy.ErrHTTPPayloadTooLarge {
		eprint("\r")
		return cli.Exit("error: file too large, or clipboard full", 1)
	}
	if err == pcopy.ErrHTTPTooManyRequests {
		eprint("\r")
		return cli.Exit("error: too many files in clipboard, or rate limit reached", 1)
	}
	return err
}

func createInteractiveReader(reader io.Reader, errWriter io.Writer) io.ReadCloser {
	fmt.Fprintln(errWriter, "(Reading from STDIN, use Ctrl-D will send)")
	fmt.Fprintln(errWriter)

	lines := make([]string, 0)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		lines = append(lines, scanner.Text()+"\n")
	}
	content := strings.Join(lines, "")
	return io.NopCloser(strings.NewReader(content))
}

func execPaste(c *cli.Context) error {
	config, id, files, err := parseClientArgs(c)
	if err != nil {
		return err
	}
	client, err := pcopy.NewClient(config)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		if err := client.PasteFiles(files[0], id); err != nil {
			return err
		}
	} else {
		if err := client.Paste(c.App.Writer, id); err != nil {
			return err
		}
	}
	return nil
}

func parseClientArgs(c *cli.Context) (*pcopy.Config, string, []string, error) {
	configFileOverride := c.String("config")
	certFile := c.String("cert")
	serverAddr := c.String("server")
	quiet := c.Bool("quiet")

	// Parse clipboard, id and files
	clipboard, id, files, err := parseClipboardIDAndFiles(c.Args(), configFileOverride)
	if err != nil {
		return nil, "", nil, err
	}

	// Load config
	configFile, config, err := parseAndLoadConfig(configFileOverride, clipboard)
	if err != nil {
		return nil, "", nil, err
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
		config.ProgressFunc = func(processed int64, total int64, done bool) {
			progressOutput(c.App.ErrWriter, processed, total, done)
		}
	}
	if os.Getenv("PCOPY_KEY") != "" {
		config.Key, err = pcopy.DecodeKey(os.Getenv("PCOPY_KEY"))
		if err != nil {
			return nil, "", nil, err
		}
	}

	return config, id, files, nil
}

func parseClipboardIDAndFiles(args cli.Args, configFileOverride string) (string, string, []string, error) {
	clipboard := pcopy.DefaultClipboard
	id := pcopy.DefaultID
	files := make([]string, 0)
	if args.Len() > 0 {
		var err error
		clipboard, id, err = parseClipboardAndID(args.Get(0), configFileOverride)
		if err != nil {
			return "", "", nil, err
		}
	}
	if args.Len() > 1 {
		files = args.Slice()[1:]
	}
	return clipboard, id, files, nil
}

func parseClipboardAndID(clipboardAndID string, configFileOverride string) (string, string, error) {
	clipboard := pcopy.DefaultClipboard
	id := pcopy.DefaultID
	re := regexp.MustCompile(`^(?i)(?:([-_a-z0-9]*):)?(|[a-z0-9][-_.a-z0-9]*)$`)
	parts := re.FindStringSubmatch(clipboardAndID)
	if len(parts) != 3 {
		return "", "", errors.New("invalid argument, must be in format [CLIPBOARD:]ID")
	}
	if parts[1] != "" {
		if configFileOverride != "" {
			return "", "", errors.New("invalid argument, -config cannot be set when clipboard is given")
		}
		clipboard = parts[1]
	}
	if parts[2] != "" {
		id = parts[2]
	}
	return clipboard, id, nil
}

var previousProgressLen int

func progressOutput(errWriter io.Writer, processed int64, total int64, done bool) {
	if done {
		if previousProgressLen > 0 {
			progress := fmt.Sprintf("%s (100%%)", pcopy.BytesToHuman(processed))
			progressWithSpaces := progress
			if len(progress) < previousProgressLen {
				progressWithSpaces += strings.Repeat(" ", previousProgressLen-len(progress))
			}
			fmt.Fprintf(errWriter, "\r%s\r\n", progressWithSpaces)
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
		fmt.Fprintf(errWriter, "\r%s", progressWithSpaces)
		previousProgressLen = len(progress)
	}
}
