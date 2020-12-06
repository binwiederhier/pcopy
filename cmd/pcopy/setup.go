package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"pcopy"
	"strings"
	"syscall"
	"time"
)

func execSetup(args []string) {
	flags := flag.NewFlagSet("setup", flag.ExitOnError)
	flags.Usage = showSetupUsage
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("pcopy server setup")
	fmt.Println("--")

	fmt.Println("The listen address is used to bind the local server.")
	fmt.Printf("Listen address (default: :%d): ", pcopy.DefaultPort)
	listenAddr, _ := reader.ReadString('\n')
	listenAddr = strings.Trim(listenAddr, "\n")
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", pcopy.DefaultPort)
	}
	fmt.Println()

	hostname, err := os.Hostname()
	if err != nil {
		fail(err)
	}
	fmt.Println("The hostname will be used to advertise to clients. It must be resolvable by clients.")
	fmt.Printf("Hostname (default: %s): ", hostname)
	serverAddr, _ := reader.ReadString('\n')
	serverAddr = strings.Trim(serverAddr, "\n")
	if serverAddr == "" {
		serverAddr = hostname
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

	var key *pcopy.Key
	if string(password) != "" {
		key, err = pcopy.GenerateKey(password)
		if err != nil {
			fail(err)
		}
	}

	pemKey, pemCert := generateKeyAndCert()
	config := generateConfig(listenAddr, serverAddr, key)

	configFile := pcopy.GetConfigFileForAlias("server")
	keyFile := strings.TrimSuffix(configFile, ".conf") + ".key" // TODO fix me
	certFile := strings.TrimSuffix(configFile, ".conf") + ".crt"

	ioutil.WriteFile(configFile, []byte(config), 0644)
	ioutil.WriteFile(keyFile, []byte(pemKey), 0600)
	ioutil.WriteFile(certFile, []byte(pemCert), 0644)

	fmt.Printf("Server config written to %s, with key/cert file next to it\n", configFile)
}

func generateConfig(listenAddr string, serverAddr string, key *pcopy.Key) string {
	if key != nil {
		return fmt.Sprintf("ListenAddr %s\nServerAddr %s\nKey %s\n", listenAddr, serverAddr, pcopy.EncodeKey(key))
	} else {
		return fmt.Sprintf("ListenAddr %s\nServerAddr %s\n", listenAddr, serverAddr)
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func generateKeyAndCert() (string, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "pcopy"},
		NotBefore: time.Now().Add(-time.Hour * 24 * 7),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pemCert := out.String()

	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
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
