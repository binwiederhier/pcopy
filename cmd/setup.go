package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	serviceFile        = "/lib/systemd/system/pcopy.service"
	defaultServiceUser = "pcopy"
)

var cmdSetup = &cli.Command{
	Name:     "setup",
	Usage:    "Initial setup wizard for a new pcopy server",
	Action:   execSetup,
	Category: categoryServer,
	Description: `Starts an interactive wizard to generate server config, private key and certificate.
This command must be run as root, since it (potentially) creates users and installs a
systemd service.

Examples:
  sudo pcopy setup   # Install pcopy server to /etc/pcopy with 'pcopy' user
  pcopy setup        # Install pcopy server to ~/.config/pcopy for current user`,
}

type wizard struct {
	config  *config.Config
	reader  *bufio.Reader
	context *cli.Context

	configFile     string
	clipboardDir   string
	installService bool
	hasService     bool
	serviceUser    string
	uid            int
	gid            int
}

func execSetup(c *cli.Context) error {
	setup := &wizard{
		config:  config.New(),
		reader:  bufio.NewReader(c.App.Reader),
		context: c,
	}

	fmt.Fprintln(c.App.ErrWriter, "pcopy server setup")
	fmt.Fprintln(c.App.ErrWriter, "--")

	// TODO check overwrite config file
	// TODO write access to config file

	// Ask questions and populate the config & wizard struct
	setup.askUser()
	setup.askConfigFile()
	setup.askClipboardDir()
	setup.askListenAddr()
	setup.askServerAddr()
	setup.askPassword()
	if setup.serviceUser == defaultServiceUser {
		setup.askService()
	}
	setup.askConfirm()

	// Do stuff
	if setup.serviceUser == defaultServiceUser {
		setup.createUserAndGroup()
	}
	setup.createClipboardDir()
	setup.writeConfigFile()
	setup.writeKeyAndCert()
	if setup.installService {
		setup.writeSystemdUnit()
	}

	setup.printSuccess()
	return nil
}

func (w *wizard) askUser() {
	u, err := user.Current()
	if err != nil {
		w.fail(err)
	}
	if u.Uid == "0" || u.Name == defaultServiceUser {
		w.serviceUser = defaultServiceUser
	} else {
		fmt.Fprintln(w.context.App.ErrWriter, "You are not root. To be able to install a systemd service for the pcopy")
		fmt.Fprintln(w.context.App.ErrWriter, "server, please re-run this wizard as a super user: 'sudo pcopy setup'.")
		fmt.Fprintf(w.context.App.ErrWriter, "To setup a pcopy server for user %s, simply continue the wizard.\n", u.Name)
		fmt.Fprintln(w.context.App.ErrWriter)

		w.serviceUser = u.Name
		w.uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			w.fail(err)
		}
		w.gid, err = strconv.Atoi(u.Gid)
		if err != nil {
			w.fail(err)
		}
	}
}

func (w *wizard) askConfigFile() {
	var defaultConfigFile string
	if w.serviceUser == defaultServiceUser {
		defaultConfigFile = config.DefaultServerConfigFile
	} else {
		defaultConfigFile = "~/.config/pcopy/server.conf"
	}
	fmt.Fprintln(w.context.App.ErrWriter, "The config file is where all of this server'w configuration will be stored.")
	fmt.Fprintf(w.context.App.ErrWriter, "Config file (default: %s): ", defaultConfigFile)
	configFile := w.readLine()
	if configFile != "" {
		w.configFile = util.ExpandHome(configFile)
	} else {
		w.configFile = util.ExpandHome(defaultConfigFile)
	}
	fmt.Fprintln(w.context.App.ErrWriter)
}

func (w *wizard) askClipboardDir() {
	var defaultClipboardDir string
	if w.serviceUser == defaultServiceUser {
		defaultClipboardDir = config.DefaultClipboardDir
	} else {
		defaultClipboardDir = "~/.cache/pcopy"
	}
	fmt.Fprintln(w.context.App.ErrWriter, "The clipboard dir is where the clipboard contents are stored.")
	fmt.Fprintf(w.context.App.ErrWriter, "Clipboard dir (default: %s): ", defaultClipboardDir)
	clipboardDir := w.readLine()
	if clipboardDir != "" {
		w.config.ClipboardDir = util.ExpandHome(clipboardDir)
		w.clipboardDir = util.ExpandHome(clipboardDir)
	} else {
		if w.serviceUser != defaultServiceUser {
			w.config.ClipboardDir = defaultClipboardDir
		}
		w.clipboardDir = util.ExpandHome(defaultClipboardDir)
	}
	fmt.Fprintln(w.context.App.ErrWriter)
}

func (w *wizard) askListenAddr() {
	fmt.Fprintln(w.context.App.ErrWriter, "The listen address is used to bind the local server for HTTPS connections.")
	fmt.Fprintf(w.context.App.ErrWriter, "Listen address (default: :%d): ", config.DefaultPort)
	w.config.ListenHTTPS = w.readLine()
	fmt.Fprintln(w.context.App.ErrWriter)
}

func (w *wizard) askServerAddr() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	fmt.Fprintln(w.context.App.ErrWriter, "The hostname will be used to advertise to clients. It must be resolvable by clients.")
	fmt.Fprintf(w.context.App.ErrWriter, "Hostname (default: %s): ", hostname)
	serverAddr := w.readLine()
	if serverAddr != "" {
		w.config.ServerAddr = serverAddr
	} else {
		w.config.ServerAddr = hostname
	}
	fmt.Fprintln(w.context.App.ErrWriter)
}

func (w *wizard) askPassword() {
	fmt.Fprintln(w.context.App.ErrWriter, "To protect the server with a key, enter a password. A key will be derived from it.")
	fmt.Fprint(w.context.App.ErrWriter, "Password: ")
	password, err := util.ReadPassword(w.reader)
	if err != nil {
		w.fail(err)
	}
	fmt.Fprintln(w.context.App.ErrWriter)
	fmt.Fprintln(w.context.App.ErrWriter)
	if string(password) != "" {
		w.config.Key, err = crypto.GenerateKey(password)
		if err != nil {
			w.fail(err)
		}
	}
}

func (w *wizard) readLine() string {
	line, err := w.reader.ReadString('\n')
	if err != nil {
		w.fail(err)
	}
	return strings.TrimSpace(line)
}

func (w *wizard) askService() {
	if _, err := os.Stat(serviceFile); err != nil {
		fmt.Fprintln(w.context.App.ErrWriter, "If your system supports systemd, installing the pcopy server as a service is recommended.")
		fmt.Fprint(w.context.App.ErrWriter, "Install systemd service? [Y/n] ")
		answer := strings.ToLower(w.readLine())
		w.installService = answer == "y" || answer == ""
		w.hasService = w.installService
		fmt.Fprintln(w.context.App.ErrWriter)
	} else {
		w.installService = false
		w.hasService = true
	}
}

func (w *wizard) askConfirm() {
	fmt.Fprintln(w.context.App.ErrWriter, "Summary")
	fmt.Fprintln(w.context.App.ErrWriter, "--")
	fmt.Fprintln(w.context.App.ErrWriter, "We're ready to go. Please review the summary and continue if you're")
	fmt.Fprintln(w.context.App.ErrWriter, "happy with what you see:")
	fmt.Fprintln(w.context.App.ErrWriter)
	if w.serviceUser == defaultServiceUser {
		fmt.Fprintln(w.context.App.ErrWriter, "Users to be created:")
		fmt.Fprintf(w.context.App.ErrWriter, "- User: %s (to run 'pcopy serve')\n", w.serviceUser)
		fmt.Fprintln(w.context.App.ErrWriter)
	}
	fmt.Fprintln(w.context.App.ErrWriter, "Files to be created:")
	fmt.Fprintf(w.context.App.ErrWriter, "- Clipboard dir:     %s\n", util.CollapseHome(w.clipboardDir))
	fmt.Fprintf(w.context.App.ErrWriter, "- Config file:       %s\n", util.CollapseHome(w.configFile))
	fmt.Fprintf(w.context.App.ErrWriter, "- Private key file:  %s\n", util.CollapseHome(config.DefaultKeyFile(w.configFile, false)))
	fmt.Fprintf(w.context.App.ErrWriter, "- Certificate file:  %s\n", util.CollapseHome(config.DefaultCertFile(w.configFile, false)))
	if w.installService {
		fmt.Fprintf(w.context.App.ErrWriter, "- Systemd unit file: %s\n", serviceFile)
	}
	fmt.Fprintln(w.context.App.ErrWriter)

	fmt.Fprint(w.context.App.ErrWriter, "Would you like to continue? [Y/n] ")
	answer := strings.ToLower(w.readLine())
	if answer != "y" && answer != "" {
		w.fail(errors.New("user aborted"))
	}
	fmt.Fprintln(w.context.App.ErrWriter)
}

func (w *wizard) createClipboardDir() {
	fmt.Fprintf(w.context.App.ErrWriter, "Creating clipboard directory %s ... ", util.CollapseHome(w.clipboardDir))
	if err := os.MkdirAll(w.clipboardDir, 0700); err != nil {
		w.fail(err)
	}
	if err := os.Chown(w.clipboardDir, w.uid, w.gid); err != nil {
		w.fail(err)
	}
	fmt.Fprintln(w.context.App.ErrWriter, "ok")
}

func (w *wizard) writeConfigFile() {
	fmt.Fprintf(w.context.App.ErrWriter, "Writing server config file %s ... ", util.CollapseHome(w.configFile))
	if err := w.config.WriteFile(w.configFile); err != nil {
		w.fail(err)
	}
	if err := os.Chown(filepath.Dir(w.configFile), w.uid, w.gid); err != nil {
		w.fail(err)
	}
	if err := os.Chown(w.configFile, w.uid, w.gid); err != nil {
		w.fail(err)
	}
	fmt.Fprintln(w.context.App.ErrWriter, "ok")
}

func (w *wizard) writeKeyAndCert() {
	serverURL, err := url.ParseRequestURI(config.ExpandServerAddr(w.config.ServerAddr))
	if err != nil {
		w.fail(err)
	}
	pemKey, pemCert, err := crypto.GenerateKeyAndCert(serverURL.Hostname())
	if err != nil {
		w.fail(err)
	}

	keyFile := config.DefaultKeyFile(w.configFile, false)
	fmt.Fprintf(w.context.App.ErrWriter, "Writing private key file %s ... ", util.CollapseHome(keyFile))
	if err := ioutil.WriteFile(keyFile, []byte(pemKey), 0600); err != nil {
		w.fail(err)
	}
	if err := os.Chown(keyFile, w.uid, w.gid); err != nil {
		w.fail(err)
	}
	fmt.Fprintln(w.context.App.ErrWriter, "ok")

	certFile := config.DefaultCertFile(w.configFile, false)
	fmt.Fprintf(w.context.App.ErrWriter, "Writing certificate %s ... ", util.CollapseHome(certFile))
	if err := ioutil.WriteFile(certFile, []byte(pemCert), 0644); err != nil {
		w.fail(err)
	}
	if err := os.Chown(certFile, w.uid, w.gid); err != nil {
		w.fail(err)
	}
	fmt.Fprintln(w.context.App.ErrWriter, "ok")
}

func (w *wizard) writeSystemdUnit() {
	fmt.Fprintf(w.context.App.ErrWriter, "Writing systemd unit file %s ... ", serviceFile)
	if err := ioutil.WriteFile(serviceFile, []byte(config.SystemdUnit), 0644); err != nil {
		w.fail(err)
	}
	fmt.Fprintln(w.context.App.ErrWriter, "ok")
}

func (w *wizard) createUserAndGroup() {
	fmt.Fprintf(w.context.App.ErrWriter, "Creating user %s ... ", w.serviceUser)
	u, err := user.Lookup(w.serviceUser)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			cmd := exec.Command("useradd", w.serviceUser)
			err := cmd.Run()
			if err != nil {
				w.fail(err)
			}
			u, err = user.Lookup(w.serviceUser)
			if err != nil {
				w.fail(err)
			}
			fmt.Fprintln(w.context.App.ErrWriter, "ok")
		} else {
			w.fail(err)
		}
	} else {
		fmt.Fprintln(w.context.App.ErrWriter, "exists")
	}
	w.uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		w.fail(err)
	}
	w.gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		w.fail(err)
	}
}

func (w *wizard) printSuccess() {
	fmt.Fprintln(w.context.App.ErrWriter)
	fmt.Fprintln(w.context.App.ErrWriter, "Success. You may now start the server by running:")
	fmt.Fprintln(w.context.App.ErrWriter)
	if w.hasService {
		fmt.Fprintln(w.context.App.ErrWriter, "  $ sudo systemctl start pcopy")
	} else {
		if w.serviceUser == defaultServiceUser {
			fmt.Fprintln(w.context.App.ErrWriter, "  $ sudo -u pcopy pcopy serve")
		} else {
			fmt.Fprintln(w.context.App.ErrWriter, "  $ pcopy serve")
		}
	}
	fmt.Fprintln(w.context.App.ErrWriter)
}

func (w *wizard) fail(err error) {
	fmt.Fprintln(w.context.App.ErrWriter, err.Error())
	os.Exit(1)
}
