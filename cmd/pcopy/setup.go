package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"pcopy"
	"strings"
	"syscall"
	"text/template"
	"time"
)

func execSetup(args []string) {
	flags := flag.NewFlagSet("setup", flag.ExitOnError)
	flags.Usage = showSetupUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	reader := bufio.NewReader(os.Stdin)
	config := pcopy.DefaultConfig

	fmt.Println("pcopy server setup")
	fmt.Println("--")

	fmt.Println("The listen address is used to bind the local server.")
	fmt.Printf("Listen address (default: %s): ", config.ListenAddr)
	listenAddr := readLine(reader)
	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}
	fmt.Println()

	fmt.Println("The hostname will be used to advertise to clients. It must be resolvable by clients.")
	fmt.Printf("Hostname (default: %s): ", config.ServerAddr)
	serverAddr := readLine(reader)
	if serverAddr == "" {
		config.ServerAddr = serverAddr
	}
	fmt.Println()

	fmt.Println("To protect the server with a key, enter a password. A key will be derived from it.")
	fmt.Print("Password (default: empty): ")
	password, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		fail(err)
	}
	fmt.Println()
	fmt.Println()

	if string(password) != "" {
		config.Key, err = pcopy.GenerateKey(password)
		if err != nil {
			fail(err)
		}
	}

	configFile := pcopy.GetConfigFileForAlias("server")
	keyFile := strings.TrimSuffix(configFile, ".conf") + ".key" // TODO fix me
	certFile := strings.TrimSuffix(configFile, ".conf") + ".crt"

	pemKey, pemCert := generateKeyAndCert()

	// Write config file
	// TODO use config.write()
	configDir := filepath.Dir(configFile)
	if err := os.MkdirAll(configDir, 0744); err != nil {
		fail(err)
	}

	configFp, err := os.OpenFile(configFile, os.O_CREATE | os.O_WRONLY, 0600)
	if err != nil {
		fail(err)
	}
	if err := serverConfigTemplate.Execute(configFp, config); err != nil {
		fail(err)
	}

	// Write key and cert
	if err := ioutil.WriteFile(keyFile, []byte(pemKey), 0600); err != nil {
		fail(err)
	}
	if err := ioutil.WriteFile(certFile, []byte(pemCert), 0644); err != nil {
		fail(err)
	}

	fmt.Printf("Server config written to %s, with key/cert file next to it\n", configFile)
}

func readLine(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil {
		fail(err)
	}
	return strings.TrimSpace(line)
}

func generateKeyAndCert() (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		fail(err)
	}
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "pcopy"},
		NotBefore: time.Now().Add(-time.Hour * 24 * 7),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 3),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		fail(err)
	}

	out := &bytes.Buffer{}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fail(err)
	}
	pemCert := out.String()

	out.Reset()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fail(err)
	}
	if err := pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		fail(err)
	}
	pemKey := out.String()

	return pemKey, pemCert
}

func showSetupUsage() {
	fmt.Println("Usage: pcopy setup")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Starts an interactive wizard to generate server config, private key and certificate.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pcopy setup")
	syscall.Exit(1)
}

var templateFuncMap = template.FuncMap{"encodeKey": pcopy.EncodeKey}
var serverConfigTemplate = template.Must(template.New("").Funcs(templateFuncMap).Parse(
`# pcopy server config file

# Address and port to use to bind the server. To bind to all addresses, you may
# omit the address, e.g. :2586.
# 
# Format:  [ADDR]:PORT
# Default: :1986
#
ListenAddr {{.ListenAddr}}

# Hostname to be advertised to clients. This is used by clients to communicate with
# the server. It is not strictly necessary for normal copy/paste operations, but required
# for the easy-install process via 'pcopy invite'. If PORT is not defined, the default 
# port 1986 is used. 
# 
# Format:  HOST[:PORT]
# Default: None
#
ServerAddr {{.ServerAddr}}

# If a key is defined, clients need to auth whenever they want copy/paste values
# to the clipboard. A key is derived from a password and can be generated using
# the 'pcopy keygen' command.
# 
# Format:  SALT:KEY (both base64 encoded)
# Default: None
#
{{if .Key}}Key {{encodeKey .Key}}{{else}}# Key{{end}}

# Path to the TLS certificate served to the clients. If not set, the config file path (with 
# a .crt extension) is assumed to be the path to the certificate, e.g. server.crt (if the config
# file is server.conf). 
#
# Format:  /some/path/to/server.crt (PEM formatted)
# Default: Config path, but with .crt extension
#
{{if .CertFile}}CertFile {{.CertFile}}{{else}}# CertFile{{end}}

# Path to the private key for the matching certificate. If not set, the config file path (with 
# a .key extension) is assumed to be the path to the private key, e.g. server.key (if the config
# file is server.conf).
#
# Format:  /some/path/to/server.key (PEM formatted)
# Default: Config path, but with .key extension
#
{{if .KeyFile}}KeyFile {{.KeyFile}}{{else}}# KeyFile{{end}}

# Path to the directory in which the clipboard resides. If not set, this defaults to 
# the path /var/cache/pcopy.
#
# Format:  /some/folder
# Default: /var/cache/pcopy
#
{{if .CacheDir}}CacheDir {{.CacheDir}}{{else}}# CacheDir{{end}}
`))