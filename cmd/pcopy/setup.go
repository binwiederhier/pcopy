package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"heckel.io/pcopy"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	serviceFile = "/lib/systemd/system/pcopy.service"
	serviceUser = "pcopy"
)

type wizard struct {
	config *pcopy.Config
	reader *bufio.Reader

	configFile   string
	clipboardDir string
	service      bool
	uid          int
	gid          int
}

func execSetup(args []string) {
	flags := flag.NewFlagSet("pcopy setup", flag.ExitOnError)
	configFile := flags.String("config", pcopy.DefaultServerConfigFile, "Config file this wizard will write")
	flags.Usage = showSetupUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	setup := &wizard{
		config: &pcopy.Config{},
		reader: bufio.NewReader(os.Stdin),
		configFile: *configFile,
	}

	fmt.Println("pcopy server setup")
	fmt.Println("--")

	// TODO check root
	// TODO check overwrite config file
	// TODO write access to config file

	// Ask questions and populate the config & wizard struct
	setup.askListenAddr()
	setup.askServerAddr()
	setup.askClipboardDir()
	setup.askPassword()
	setup.askService()

	// TODO summary

	// Do stuff
	setup.createUserAndGroup()
	setup.createClipboardDir()
	setup.writeConfigFile()
	setup.writeKeyAndCert()
	if setup.service {
		setup.writeSystemdUnit()
	}

	fmt.Println("Done.")
}

func (s *wizard) askListenAddr() {
	fmt.Println("The listen address is used to bind the local server.")
	fmt.Printf("Listen address (default: :%d): ", pcopy.DefaultPort)
	s.config.ListenAddr = s.readLine()
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

func (s *wizard) askClipboardDir() {
	fmt.Println("The clipboard dir is where the clipboard contents are stored.")
	fmt.Printf("Clipboard dir (default: %s): ", pcopy.DefaultClipboardDir)
	clipboardDir := s.readLine()
	if clipboardDir != "" {
		s.config.ClipboardDir = clipboardDir
	} else {
		s.clipboardDir = pcopy.DefaultClipboardDir
	}
	fmt.Println()
}

func (s *wizard) askPassword() {
	fmt.Println("To protect the server with a key, enter a password. A key will be derived from it.")
	fmt.Print("Password: ")
	password, err := terminal.ReadPassword(syscall.Stdin)
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
		fmt.Print("Install systemd service [Y/n]?: ")
		answer := strings.ToLower(s.readLine())
		s.service = answer == "y" || answer == ""
		fmt.Println()
	}
}

func (s *wizard) createClipboardDir() {
	fmt.Printf("Creating clipboard directory %s ... ", s.clipboardDir)
	if err := os.MkdirAll(s.clipboardDir, 0700); err != nil {
		fail(err)
	}
	if err := os.Chown(s.clipboardDir, s.uid, s.gid); err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func (s *wizard) writeConfigFile() {
	fmt.Printf("Writing server config file %s ... ", s.configFile)
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
	pemKey, pemCert, err := pcopy.GenerateKeyAndCert()
	if err != nil {
		fail(err)
	}

	keyFile := pcopy.DefaultKeyFile(s.configFile, false)
	fmt.Printf("Writing private key file %s ... ", keyFile)
	if err := ioutil.WriteFile(keyFile, []byte(pemKey), 0600); err != nil {
		fail(err)
	}
	if err := os.Chown(keyFile, s.uid, s.gid); err != nil {
		fail(err)
	}
	fmt.Println("ok")

	certFile := pcopy.DefaultCertFile(s.configFile, false)
	fmt.Printf("Writing certificate %s ... ", certFile)
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
	if err := ioutil.WriteFile(serviceFile, []byte(systemdUnit), 0644); err != nil {
		fail(err)
	}
	fmt.Println("ok")
}

func (s *wizard) createUserAndGroup() {
	u, err := user.Lookup(serviceUser)
	if _, ok := err.(*user.UnknownUserError); ok {
		cmd := exec.Command("useradd", serviceUser)
		err := cmd.Run()
		if err != nil {
			fail(err)
		}
		u, err = user.Lookup(serviceUser)
		if err != nil {
			fail(err)
		}
	} else if err != nil {
		fail(err)
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

func showSetupUsage() {
	fmt.Println("Usage: pcopy setup")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Starts an interactive wizard to generate server config, private key and certificate.")
	fmt.Println("  This command must be run as root, since it (potentially) creates users and installs a")
	fmt.Println("  systemd service.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sudo pcopy setup")
	syscall.Exit(1)
}

const systemdUnit = `[Unit]
Description=pcopy server
After=network.target

[Service]
ExecStart=/usr/bin/pcopy serve
Restart=on-failure
User=pcopy
Group=pcopy

[Install]
WantedBy=multi-user.target
`