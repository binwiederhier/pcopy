package pcopy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ServerRouter is a simple vhost delegator to be able to run multiple clipboards on the same port.
// It runs the actual HTTP(S) servers and delegates based on the configured hostname.
type ServerRouter struct {
	servers  []*Server
	handler  http.Handler
	srvHTTP  *http.Server
	srvHTTPS *http.Server
	mu       sync.Mutex
}

// Serve starts a server and listens for incoming HTTPS requests. The server handles all management operations (info,
// verify, ...), as well as the actual clipboard functionality (GET/PUT/POST). It also starts a background process
// to prune old.
//
// The function supports many configs, multiplexing based on the HTTP "Host:" header to the individual Server instances.
// If more than one config is passed, the "ListenAddr" configuration setting must be identical for all of them.
func Serve(configs ...*Config) error {
	router, err := NewServerRouter(configs...)
	if err != nil {
		return err
	}
	return router.Start()
}

// NewServerRouter creates a new multi-clipboard server using the given configs.
//
// The function supports many configs, multiplexing based on the HTTP "Host:" header to the individual Server instances.
// If more than one config is passed, the "ListenAddr" configuration setting must be identical for all of them.
func NewServerRouter(configs ...*Config) (*ServerRouter, error) {
	var err error
	if err := checkConfigs(configs); err != nil {
		return nil, err
	}
	servers, err := createServers(configs)
	if err != nil {
		return nil, err
	}
	handler, err := createHandler(servers)
	if err != nil {
		return nil, err
	}
	return &ServerRouter{servers: servers, handler: handler}, nil
}

// Start starts the HTTP(S) server
func (r *ServerRouter) Start() error {
	r.printListenInfo()
	errChan := make(chan error)
	if r.servers[0].config.ListenHTTP != "" {
		r.mu.Lock()
		r.srvHTTP = &http.Server{Addr: r.servers[0].config.ListenHTTP, Handler: r.handler}
		r.mu.Unlock()
		go func() {
			if err := r.srvHTTP.ListenAndServe(); err != nil {
				errChan <- err
			}
		}()
	}
	if r.servers[0].config.ListenHTTPS != "" {
		r.mu.Lock()
		r.srvHTTPS = &http.Server{Addr: r.servers[0].config.ListenHTTPS, Handler: r.handler}
		r.mu.Unlock()
		go func() {
			tlsConfig := &tls.Config{Certificates: make([]tls.Certificate, len(r.servers))}
			for i, s := range r.servers {
				var err error
				tlsConfig.Certificates[i], err = tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
				if err != nil {
					errChan <- err
					return
				}
			}
			listener, err := tls.Listen("tcp", r.servers[0].config.ListenHTTPS, tlsConfig)
			if err != nil {
				errChan <- err
				return
			}
			if err := r.srvHTTPS.Serve(listener); err != nil {
				errChan <- err
				return
			}
		}()
	}
	for _, server := range r.servers {
		go server.serverManager()
	}
	err := <-errChan
	return err
}

// Stop immediately shuts down the HTTP(S) server. This is not a graceful shutdown.
func (r *ServerRouter) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srvHTTP != nil {
		if err := r.srvHTTP.Close(); err != nil {
			return err
		}
	}
	if r.srvHTTPS != nil {
		if err := r.srvHTTPS.Close(); err != nil {
			return err
		}
	}
	r.srvHTTP = nil
	r.srvHTTPS = nil
	return nil
}

func (r *ServerRouter) printListenInfo() {
	listens := make([]string, 0)
	if r.servers[0].config.ListenHTTP != "" {
		listens = append(listens, fmt.Sprintf("%s/http", r.servers[0].config.ListenHTTP))
	}
	if r.servers[0].config.ListenHTTPS != "" {
		listens = append(listens, fmt.Sprintf("%s/https", r.servers[0].config.ListenHTTPS))
	}
	log.Printf("Listening on %s (%d clipboard(s))\n", strings.Join(listens, " "), len(r.servers))
}

func createHandler(servers []*Server) (*http.ServeMux, error) {
	handler := http.NewServeMux()
	for i, server := range servers {
		serverURL, err := url.ParseRequestURI(ExpandServerAddr(server.config.ServerAddr))
		if err != nil {
			return nil, err
		}
		handler.HandleFunc(fmt.Sprintf("%s/", serverURL.Hostname()), servers[i].handle)
	}
	return handler, nil
}

func createServers(configs []*Config) ([]*Server, error) {
	servers := make([]*Server, len(configs))
	for i, config := range configs {
		var err error
		servers[i], err = NewServer(config)
		if err != nil {
			return nil, err
		}
	}
	return servers, nil
}

func checkConfigs(configs []*Config) error {
	if len(configs) == 0 {
		return errInvalidNumberOfConfigs
	}
	for _, config := range configs {
		if config.ListenHTTP != configs[0].ListenHTTP {
			return errors.New("config setting 'ListenHTTP' must be identical in all config files")
		}
		if config.ListenHTTPS != configs[0].ListenHTTPS {
			return errors.New("config setting 'ListenHTTP' must be identical in all config files")
		}
	}
	return nil
}

var errInvalidNumberOfConfigs = errors.New("invalid number of configs, need at least one")
