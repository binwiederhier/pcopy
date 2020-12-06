package main

import (
	"crypto/x509"
	"os"
	"pcopy"
)

func execInvite(args []string)  {
	config, _ := parseClientArgs("invite", args)

	var certs []*x509.Certificate
	if config.CertFile != "" {
		if _, err := os.Stat(config.CertFile); err == nil {
			certs, err = pcopy.LoadCerts(config.CertFile)
			if err != nil {
				fail(err)
			}
		}
	}

	println(curlCommand("join", config.ServerAddr, certs, config.Key))
}