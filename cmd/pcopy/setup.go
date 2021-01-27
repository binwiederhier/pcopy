package main

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
	"heckel.io/pcopy"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	config *pcopy.Config
	reader *bufio.Reader

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
		config: &pcopy.Config{},
		reader: bufio.NewReader(os.Stdin),
	}

	fmt.Println("pcopy server setup")
	fmt.Println("--")

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

func (s *wizard) askUser() {
	u, err := user.Current()
	if err != nil {
		fail(err)
	}
	if u.Uid == "0" || u.Name == defaultServiceUser {
		s.serviceUser = defaultServiceUser
	} else {
		fmt.Println("You are not root. To be able to install a systemd service for the pcopy")
		fmt.Println("server, please re-run this wizard as a super user: 'sudo pcopy setup'.")
		fmt.Printf("To setup a pcopy server for user %s, simply continue the wizard.\n", u.Name)
		fmt.Println()

		s.serviceUser = u.Name
		s.uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			fail(err)
		}
		s.gid, err = strconv.Atoi(u.Gid)
		if err != nil {
			fail(err)
		}
	}
}

func (s *wizard) askConfigFile() {
	var defaultConfigFile string
	if s.serviceUser == defaultServiceUser {
		defaultConfigFile = pcopy.DefaultServerConfigFile
	} else {
		defaultConfigFile = "~/.config/pcopy/server.conf"
	}
	fmt.Println("The config file is where all of this server's configuration will be stored.")
	fmt.Printf("Config file (default: %s): ", defaultConfigFile)
	configFile := s.readLine()
	if configFile != "" {
		s.configFile = pcopy.ExpandHome(configFile)
	} else {
		s.configFile = pcopy.ExpandHome(defaultConfigFile)
	}
	fmt.Println()
}

func (s *wizard) askClipboardDir() {
	var defaultClipboardDir string
	if s.serviceUser == defaultServiceUser {
		defaultClipboardDir = pcopy.DefaultClipboardDir
	} else {
		defaultClipboardDir = "~/.cache/pcopy"
	}
	fmt.Println("The clipboard dir is where the clipboard contents are stored.")
	fmt.Printf("Clipboard dir (default: %s): ", defaultClipboardDir)
	clipboardDir := s.readLine()
	if clipboardDir != "" {
		s.config.ClipboardDir = pcopy.ExpandHome(clipboardDir)
		s.clipboardDir = pcopy.ExpandHome(clipboardDir)
	} else {
		if s.serviceUser != defaultServiceUser {
			s.config.ClipboardDir = defaultClipboardDir
		}
		s.clipboardDir = pcopy.ExpandHome(defaultClipboardDir)
	}
	fmt.Println()
}

func (s *wizard) askListenAddr() {
	fmt.Println("The listen address is used to bind the local server for HTTPS connections.")
	fmt.Printf("Listen address (default: :%d): ", pcopy.DefaultPort)
	s.config.ListenHTTPS = s.readLine()
	fmt.Println()
}

func (s *wizard) askServerAddr() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	fmt.Println("The hostname will be used to advertise to clients. It must be resolvable by clients.")
	fmt.Printf("Hostname (default: %s): ", hostname)
	serverAddr := s.readLine()
	if serverAddr != "" {
		s.config.ServerAddr = serverAddr
	} else {
		s.config.ServerAddr = hostname
	}
	fmt.Println()
}

func (s *wizard) askPassword() {
	fmt.Println("To protect the server with a key, enter a password. A key will be derived from it.")
	fmt.Print("Password: ")
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Println()
	fmt.Println()
	if string(password) != "" {
		s.config.Key, err = pcopy.GenerateKey(password)
		if err != nil {
			fail(err)
		}
	}
}

func (s *wizard) readLine() string {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		fail(err)
	}
	return strings.TrimSpace(line)
}

func (s *wizard) askService() {
	if _, err := os.Stat(serviceFile); err != nil {
		fmt.Println("If your system supports systemd, installing the pcopy server as a service is recommended.")
		fmt.Print("Install systemd service? [Y/n] ")
		answer := strings.ToLower(s.readLine())
		s.installService = answer == "y" || answer == ""
		s.hasService = s.installService
		fmt.Println()
	} else {
		s.installService = false
		s.hasService = true
	}
}

func (s *wizard) askConfirm() {
	fmt.Println("Summary")
	fmt.Println("--")
	fmt.Println("We're ready to go. Please review the summary and continue if you're")
	fmt.Println("happy with what you see:")
	fmt.Println()
	if s.serviceUser == defaultServiceUser {
		fmt.Println("Users to be created:")
		fmt.Printf("- User: %s (to run 'pcopy serve')\n", s.serviceUser)
		fmt.Println()
	}
	fmt.Println("Files to be created:")
	fmt.Printf("- Clipboard dir:     %s\n", pcopy.CollapseHome(s.clipboardDir))
	fmt.Printf("- Config file:       %s\n", pcopy.CollapseHome(s.configFile))
	fmt.Printf("- Private key file:  %s\n", pcopy.CollapseHome(pcopy.DefaultKeyFile(s.configFile, false)))
	fmt.Printf("- Certificate file:  %s\n", pcopy.CollapseHome(pcopy.DefaultCertFile(s.configFile, false)))
	if s.installService {
		fmt.Printf("- Systemd unit file: %s\n", serviceFile)
	}
	fmt.Println()

	fmt.Print("Would you like to continue? [Y/n] ")
	answer := strings.ToLower(s.readLine())
	if answer != "y" && answer != "" {
		fail(errors.New("user aborted"))
	}
	fmt.Println()
}

func (s *wizard) createClipboardDir() {
	fmt.Printf("Creating clipboard directory %s ... ", pcopy.CollapseHome(s.clipboardDir))
	if err := os.MkdirAll(s.clipboardDir, 0700); err != nil {
		fail(err)
	}
	if err := os.Chown(s.clipboardDir, s.uid, s.gid); err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func (s *wizard) writeConfigFile() {
	fmt.Printf("Writing server config file %s ... ", pcopy.CollapseHome(s.configFile))
	if err := s.config.WriteFile(s.configFile); err != nil {
		fail(err)
	}
	if err := os.Chown(filepath.Dir(s.configFile), s.uid, s.gid); err != nil {
		fail(err)
	}
	if err := os.Chown(s.configFile, s.uid, s.gid); err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func (s *wizard) writeKeyAndCert() {
	serverURL, err := url.ParseRequestURI(pcopy.ExpandServerAddr(s.config.ServerAddr))
	if err != nil {
		fail(err)
	}
	pemKey, pemCert, err := pcopy.GenerateKeyAndCert(serverURL.Hostname())
	if err != nil {
		fail(err)
	}

	keyFile := pcopy.DefaultKeyFile(s.configFile, false)
	fmt.Printf("Writing private key file %s ... ", pcopy.CollapseHome(keyFile))
	if err := ioutil.WriteFile(keyFile, []byte(pemKey), 0600); err != nil {
		fail(err)
	}
	if err := os.Chown(keyFile, s.uid, s.gid); err != nil {
		fail(err)
	}
	fmt.Println("ok")

	certFile := pcopy.DefaultCertFile(s.configFile, false)
	fmt.Printf("Writing certificate %s ... ", pcopy.CollapseHome(certFile))
	if err := ioutil.WriteFile(certFile, []byte(pemCert), 0644); err != nil {
		fail(err)
	}
	if err := os.Chown(certFile, s.uid, s.gid); err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func (s *wizard) writeSystemdUnit() {
	fmt.Printf("Writing systemd unit file %s ... ", serviceFile)
	if err := ioutil.WriteFile(serviceFile, []byte(pcopy.SystemdUnit), 0644); err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func (s *wizard) createUserAndGroup() {
	fmt.Printf("Creating user %s ... ", s.serviceUser)
	u, err := user.Lookup(s.serviceUser)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			cmd := exec.Command("useradd", s.serviceUser)
			err := cmd.Run()
			if err != nil {
				fail(err)
			}
			u, err = user.Lookup(s.serviceUser)
			if err != nil {
				fail(err)
			}
			fmt.Println("ok")
		} else {
			fail(err)
		}
	} else {
		fmt.Println("exists")
	}
	s.uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		fail(err)
	}
	s.gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		fail(err)
	}
}

func (s *wizard) printSuccess() {
	fmt.Println()
	fmt.Println("Success. You may now start the server by running:")
	fmt.Println()
	if s.hasService {
		fmt.Println("  $ sudo systemctl start pcopy")
	} else {
		if s.serviceUser == defaultServiceUser {
			fmt.Println("  $ sudo -u pcopy pcopy serve")
		} else {
			fmt.Println("  $ pcopy serve")
		}
	}
	fmt.Println()
}
