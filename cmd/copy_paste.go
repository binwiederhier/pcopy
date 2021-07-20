package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/client"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/server"
	"heckel.io/pcopy/util"
	"io"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
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
		&cli.StringFlag{Name: "ttl", Aliases: []string{"t"}, DefaultText: "server default", Usage: "set duration the link is valid for to `TTL`"},
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
  yes | pcp --stream       # Stream contents to the other end via FIFO device`,
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
  ppaste : images/         # Extracts ZIP from default clipboard to folder images/`,
}

func execCopy(c *cli.Context) error {
	conf, id, files, err := parseClientArgs(c)
	if err != nil {
		return err
	}
	pclient, err := client.NewClient(conf)
	if err != nil {
		return err
	}

	stream := c.Bool("stream")
	link := !c.Bool("nolink")
	random := c.Bool("random")
	readonly := c.Bool("read-only")
	readwrite := c.Bool("read-write")

	if readonly && readwrite {
		return cli.Exit("error: either --read-only or --read-write are allowed, not both", 1)
	}

	// Override ID
	if id == "" {
		id = conf.DefaultID
	}
	if random {
		id = ""
	}

	// Set file mode (ro, rw)
	fileMode := ""
	if readonly {
		fileMode = config.FileModeReadOnly
	} else if readwrite {
		fileMode = config.FileModeReadWrite
	}

	// Set TTL
	ttl := time.Duration(0)
	ttlStr := c.String("ttl")
	if ttlStr != "" {
		ttl, err = util.ParseDuration(ttlStr)
		if err != nil {
			return err
		}
	}

	var fileInfo *server.File
	if stream {
		fileInfo, err = pclient.Reserve(id)
		if err != nil {
			return err
		}
		id = fileInfo.File
	}

	if link && stream {
		fmt.Fprint(c.App.ErrWriter, server.FileInfoInstructions(fileInfo))
		fmt.Fprintln(c.App.ErrWriter)
		fmt.Fprintln(c.App.ErrWriter, "# Streaming contents: upload will hold until you start downloading using any of the commands above.")
	}

	if len(files) > 0 {
		fileInfo, err = pclient.CopyFiles(files, id, ttl, fileMode, stream)
		if err != nil {
			return handleCopyError(c.App.ErrWriter, err)
		}
	} else {
		mode := os.FileMode(0)
		if stdin, ok := c.App.Reader.(*os.File); ok {
			stat, err := stdin.Stat()
			if err != nil {
				return err
			}
			mode = stat.Mode()
		}

		var reader io.ReadCloser
		if (mode & os.ModeCharDevice) == 0 {
			var ok bool
			reader, ok = c.App.Reader.(io.ReadCloser)
			if !ok {
				reader = io.NopCloser(c.App.Reader)
			}
		} else {
			reader = createInteractiveReader(c.App.Reader, c.App.ErrWriter)
		}

		fileInfo, err = pclient.Copy(reader, id, ttl, fileMode, stream)
		if err != nil {
			return handleCopyError(c.App.ErrWriter, err)
		}
	}

	if link && !stream {
		fmt.Fprint(c.App.ErrWriter, server.FileInfoInstructions(fileInfo))
	}
	return nil
}

func handleCopyError(errWriter io.Writer, err error) error {
	if err == server.ErrHTTPPartialContent {
		fmt.Fprintln(errWriter, " (interrupted by client)")
		return nil // This is not really an error!
	}
	if err == server.ErrHTTPPayloadTooLarge {
		fmt.Fprint(errWriter, "\r")
		return cli.Exit("error: file too large, or clipboard full", 1)
	}
	if err == server.ErrHTTPTooManyRequests {
		fmt.Fprint(errWriter, "\r")
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
	conf, id, files, err := parseClientArgs(c)
	if err != nil {
		return err
	}
	pclient, err := client.NewClient(conf)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		if err := pclient.PasteFiles(files[0], id); err != nil {
			return err
		}
	} else {
		if err := pclient.Paste(c.App.Writer, id); err != nil {
			return err
		}
	}
	return nil
}

func parseClientArgs(c *cli.Context) (*config.Config, string, []string, error) {
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
	configFile, conf, err := parseAndLoadConfig(configFileOverride, clipboard)
	if err != nil {
		return nil, "", nil, err
	}

	// Load defaults
	if id == "" {
		id = conf.DefaultID
	}
	if conf.CertFile == "" {
		conf.CertFile = config.DefaultCertFile(configFile, true)
	}

	// Command line overrides
	if serverAddr != "" {
		conf.ServerAddr = config.ExpandServerAddr(serverAddr)
	}
	if certFile != "" {
		conf.CertFile = certFile
	}
	if !quiet {
		conf.ProgressFunc = func(processed int64, total int64, done bool) {
			progressOutput(c.App.ErrWriter, processed, total, done)
		}
	}

	return conf, id, files, nil
}

func parseClipboardIDAndFiles(args cli.Args, configFileOverride string) (string, string, []string, error) {
	clipboard, id := config.DefaultClipboard, "" // special handling of Config.DefaultID
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
	clipboard, id := config.DefaultClipboard, "" // special handling of Config.DefaultID
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

var previousProgressLen uint32

func progressOutput(errWriter io.Writer, processed int64, total int64, done bool) {
	prevLen := int(atomic.LoadUint32(&previousProgressLen))
	if done {
		if prevLen > 0 {
			progress := fmt.Sprintf("%s (100%%)", util.BytesToHuman(processed))
			progressWithSpaces := progress
			if len(progress) < int(prevLen) {
				progressWithSpaces += strings.Repeat(" ", prevLen-len(progress))
			}
			fmt.Fprintf(errWriter, "\r%s\r\n", progressWithSpaces)
		}
	} else {
		var progress string
		if total > 0 {
			progress = fmt.Sprintf("%s / %s (%.f%%)", util.BytesToHuman(processed),
				util.BytesToHuman(total), float64(processed)/float64(total)*100)
		} else {
			progress = util.BytesToHuman(processed)
		}
		progressWithSpaces := progress
		if len(progress) < prevLen {
			progressWithSpaces += strings.Repeat(" ", prevLen-len(progress))
		}
		fmt.Fprintf(errWriter, "\r%s", progressWithSpaces)
		atomic.StoreUint32(&previousProgressLen, uint32(len(progress)))
	}
}

// parseAndLoadConfig is a helper to load the config file either from the given filename, or if that is empty, determine
// the filename based on the clipboard name.
func parseAndLoadConfig(filename string, clipboard string) (string, *config.Config, error) {
	if filename != "" {
		conf, err := config.LoadFromFile(filename)
		if err != nil {
			return "", nil, err
		}
		return filename, conf, err
	}
	store := config.NewStore()
	filename = store.FileFromName(clipboard)
	if _, err := os.Stat(filename); err != nil {
		return "", nil, err
	}
	conf, err := config.LoadFromFile(filename)
	if err != nil {
		return "", nil, err
	}
	return filename, conf, nil
}
