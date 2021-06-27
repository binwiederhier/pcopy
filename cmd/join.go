package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/client"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/server"
	"heckel.io/pcopy/util"
	"io/ioutil"
	"os"
	"strings"
)

var cmdJoin = &cli.Command{
	Name:      "join",
	Aliases:   []string{"add"},
	Usage:     "Join a remote clipboard",
	UsageText: "pcopy join [OPTIONS..] SERVER [CLIPBOARD]",
	Action:    execJoin,
	Category:  categoryClient,
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "force", Aliases: []string{"f"}, Usage: "overwrite config if it already exists"},
		&cli.BoolFlag{Name: "auto", Aliases: []string{"a"}, Usage: "automatically choose clipboard alias"},
		&cli.BoolFlag{Name: "quiet", Aliases: []string{"q"}, Usage: "do not print instructions"},
	},
	Description: `Connects to a remote clipboard with the server address SERVER. CLIPBOARD is the local alias
that can be used to identify it (default is 'default'). This command is interactive and
will write a config file to ~/.config/pcopy/$CLIPBOARD.conf (or /etc/pcopy/$CLIPBOARD.conf).

The command will ask for a password if the remote clipboard requires one, unless the PCOPY_KEY
environment variable is passed.

If the remote server's certificate is self-signed, its certificate will be downloaded to
~/.config/pcopy/$CLIPBOARD.crt (or /etc/pcopy/$CLIPBOARD.crt) and pinned for future connections.

Examples:
  pcopy join pcopy.example.com     # Joins remote clipboard as local alias 'default'
  pcopy join pcopy.work.com work   # Joins remote clipboard with local alias 'work'`,
}

func execJoin(c *cli.Context) error {
	force := c.Bool("force")
	auto := c.Bool("auto")
	quiet := c.Bool("quiet")
	if c.NArg() < 1 {
		return errors.New("missing server address, see --help for usage details")
	}
	if force && auto {
		return errors.New("cannot use both --auto and --force")
	}

	clipboard := config.DefaultClipboard
	rawServerAddr := c.Args().Get(0)
	if c.NArg() > 1 {
		clipboard = c.Args().Get(1)
	}

	// Find config file
	store := config.NewStore()
	configFile := store.FileFromName(clipboard)
	if _, err := os.Stat(configFile); err == nil && !force {
		return fmt.Errorf("config file %s exists, you may want to specify a different clipboard name, or use --force to override", configFile)
	}

	// Read basic info from server
	info, err := readServerInfo(c, rawServerAddr)
	if err != nil {
		return err
	}
	pclient, err := client.NewClient(&config.Config{ServerAddr: info.ServerAddr})
	if err != nil {
		return err
	}

	// Read and verify that password was correct (if server is secured with key)
	var key *crypto.Key

	if info.Salt != nil {
		envKey := os.Getenv(config.EnvKey)
		if envKey != "" {
			key, err = crypto.DecodeKey(envKey)
			if err != nil {
				return err
			}
		} else {
			password, err := readPassword(c)
			if err != nil {
				return err
			}
			key = crypto.DeriveKey(password, info.Salt)
			err = pclient.Verify(info.Cert, key)
			if err != nil {
				return fmt.Errorf("failed to join clipboard: %s", err.Error())
			}
		}
	}

	// Write config file
	conf := config.New()
	conf.ServerAddr = config.CollapseServerAddr(info.ServerAddr)
	conf.DefaultID = info.DefaultID
	conf.Key = key // May be nil, but that's ok
	if err := conf.WriteFile(configFile); err != nil {
		return err
	}

	// Write self-signed cert (only if Verify didn't work with secure client)
	if info.Cert != nil {
		certFile := config.DefaultCertFile(configFile, false)
		certsEncoded, err := crypto.EncodeCert(info.Cert)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(certFile, certsEncoded, 0644); err != nil {
			return err
		}
	}

	if !quiet {
		printInstructions(c, configFile, clipboard, info)
	}

	return nil
}

type serverInfoResult struct {
	addr string
	info *server.Info
	err  error
}

// readServerInfo is doing a parallel lookup for all potential server addresses. For instance, "nopaste.net"
// is expanded to ["https://nopaste.net:2586", "https://nopaste.net:443"] so we check both addresses in
// parallel and return the first one that returns, or return an error with all errors.
func readServerInfo(c *cli.Context, rawServerAddr string) (*server.Info, error) {
	fmt.Fprintf(c.App.ErrWriter, "Joining clipboard at %s ... ", rawServerAddr)

	resultChan := make(chan *serverInfoResult)
	serverAddrs := config.ExpandServerAddrsGuess(rawServerAddr)

	// Kick off parallel server info query
	for _, serverAddr := range serverAddrs {
		go func(serverAddr string) {
			pclient, _ := client.NewClient(&config.Config{ServerAddr: serverAddr})
			serverInfo, err := pclient.ServerInfo()
			if err != nil {
				resultChan <- &serverInfoResult{addr: serverAddr, err: err}
				return
			}
			resultChan <- &serverInfoResult{addr: serverAddr, info: serverInfo}
		}(serverAddr)
	}

	// Read from server channel until a success is returned
	var info *server.Info
	errs := make([]*serverInfoResult, 0)
	for i := 0; i < len(serverAddrs); i++ {
		result := <-resultChan
		if result.err == nil {
			info = result.info
			break
		}
		errs = append(errs, result)
	}

	// Format error message if none of the queries was successful
	if info == nil {
		if len(errs) == 1 {
			return nil, fmt.Errorf("failed.\nCannot connect to %s: %s", errs[0].addr, toHumanReadable(errs[0].err))
		}
		messages := make([]string, 0)
		for _, err := range errs {
			messages = append(messages, fmt.Sprintf("- %s: %s", err.addr, toHumanReadable(err.err)))
		}
		return nil, fmt.Errorf("failed.\nCannot connect to any of the servers we tried:\n%s", strings.Join(messages, "\n"))
	}

	return info, nil
}

func toHumanReadable(err error) string {
	jsone := &json.SyntaxError{}
	if errors.As(err, &jsone) { // why does this have to be a double pointer?
		return "unexpected response; are you sure this a pcopy server?"
	} else if strings.Contains(err.Error(), "deadline exceeded") || strings.Contains(err.Error(), "Timeout exceeded") {
		return "timed out waiting for server"
	}
	return err.Error()
}

func readPassword(c *cli.Context) ([]byte, error) {
	fmt.Fprintf(c.App.ErrWriter, "\r%s\rEnter password to join clipboard: ", strings.Repeat(" ", 50)) // a hack ..
	password, err := util.ReadPassword(c.App.Reader)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(c.App.ErrWriter, "\r")
	return password, nil
}

func printInstructions(c *cli.Context, configFile string, clipboard string, info *server.Info) {
	clipboardPrefix := ""
	if clipboard != config.DefaultClipboard {
		clipboardPrefix = fmt.Sprintf(" %s:", clipboard)
	}

	if clipboard == config.DefaultClipboard {
		fmt.Fprintf(c.App.ErrWriter, "\rSuccessfully joined clipboard, config written to %s\n", util.CollapseHome(configFile))
	} else {
		fmt.Fprintf(c.App.ErrWriter, "\rSuccessfully joined clipboard as alias '%s', config written to %s\n", clipboard, util.CollapseHome(configFile))
	}

	if info.Cert != nil {
		fmt.Fprintln(c.App.ErrWriter)
		fmt.Fprintln(c.App.ErrWriter, "Warning: The TLS certificate was self-signed and has been pinned.")
		fmt.Fprintln(c.App.ErrWriter, "Future communication will be secure, but joining could have been intercepted.")
	}

	fmt.Fprintln(c.App.ErrWriter)
	if _, err := os.Stat("/usr/bin/pcp"); err == nil {
		fmt.Fprintf(c.App.ErrWriter, "You may now use 'pcp%s' and 'ppaste%s'. See 'pcopy -h' for usage details.\n", clipboardPrefix, clipboardPrefix)
	} else {
		fmt.Fprintf(c.App.ErrWriter, "You may now use 'pcopy copy%s' and 'pcopy paste%s'. See 'pcopy -h' for usage details.\n", clipboardPrefix, clipboardPrefix)
	}
}
