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
	srvHTTP  []*http.Server
	srvHTTPS []*http.Server
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
	if len(configs) == 0 {
		return nil, errInvalidNumberOfConfigs
	}
	servers, err := createServers(configs)
	if err != nil {
		return nil, err
	}
	return &ServerRouter{servers: servers}, nil
}

/*
config 1: :443/https :80/http
config 2: :1234/https
config 3: :2586/https
*/

// Start starts the HTTP(S) server
func (r *ServerRouter) Start() error {
	r.mu.Lock()

	var err error
	r.srvHTTP, err = r.createHTTPServers()
	if err != nil {
		return err
	}
	r.srvHTTPS, err = r.createHTTPSServers()
	if err != nil {
		return err
	}
	r.printListenInfo()

	errChan := make(chan error)
	for _, s := range r.srvHTTP {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil {
				errChan <- err
			}
		}(s)
	}
	for _, s := range r.srvHTTPS {
		go func(s *http.Server) {
			listener, err := tls.Listen("tcp", s.Addr, s.TLSConfig)
			if err != nil {
				errChan <- err
				return
			}
			if err := s.Serve(listener); err != nil {
				errChan <- err
			}
		}(s)
	}

	r.mu.Unlock()
	err = <-errChan
	return err
}

// Stop immediately shuts down the HTTP(S) server. This is not a graceful shutdown.
func (r *ServerRouter) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srvHTTP != nil {
		for _, s := range r.srvHTTP {
			if err := s.Close(); err != nil {
				return err
			}
		}
	}
	if r.srvHTTPS != nil {
		for _, s := range r.srvHTTPS {
			if err := s.Close(); err != nil {
				return err
			}
		}
	}
	r.srvHTTP = nil
	r.srvHTTPS = nil
	return nil
}

func (r *ServerRouter) printListenInfo() {
	listens := make([]string, 0)
	for _, s := range r.srvHTTP {
		listens = append(listens, fmt.Sprintf("%s/http", s.Addr))
	}
	for _, s := range r.srvHTTPS {
		listens = append(listens, fmt.Sprintf("%s/https", s.Addr))
	}
	log.Printf("Listening on %s (%d clipboard(s))\n", strings.Join(listens, " "), len(r.servers))
}

func (r *ServerRouter) createHTTPServers() ([]*http.Server, error) {
	serversPerPort := make(map[string]int, 0)
	for _, s := range r.servers {
		serversPerPort[s.config.ListenHTTP]++
	}

	servers := make(map[string]*http.Server, 0)
	for _, s := range r.servers {
		if s.config.ListenHTTP == "" {
			continue
		}
		server, ok := servers[s.config.ListenHTTP]
		if !ok {
			server = &http.Server{Addr: s.config.ListenHTTP, Handler: http.NewServeMux()}
			servers[s.config.ListenHTTP] = server
		}
		serverURL, err := url.ParseRequestURI(ExpandServerAddr(s.config.ServerAddr))
		if err != nil {
			return nil, err
		}
		handler := server.Handler.(*http.ServeMux)
		if serversPerPort[s.config.ListenHTTP] == 1 {
			handler.HandleFunc("/", s.handle)
		} else {
			handler.HandleFunc(fmt.Sprintf("%s/", serverURL.Hostname()), s.handle)
		}
	}
	serversList := make([]*http.Server, 0)
	for _, s := range servers {
		serversList = append(serversList, s)
	}
	return serversList, nil
}

func (r *ServerRouter) createHTTPSServers() ([]*http.Server, error) {
	serversPerPort := make(map[string]int, 0)
	for _, s := range r.servers {
		serversPerPort[s.config.ListenHTTPS]++
	}

	servers := make(map[string]*http.Server, 0)
	for _, s := range r.servers {
		if s.config.ListenHTTPS == "" {
			continue
		}
		server, ok := servers[s.config.ListenHTTPS]
		if !ok {
			server = &http.Server{Addr: s.config.ListenHTTPS, Handler: http.NewServeMux(), TLSConfig: &tls.Config{Certificates: make([]tls.Certificate, 0)}}
			servers[s.config.ListenHTTPS] = server
		}
		serverURL, err := url.ParseRequestURI(ExpandServerAddr(s.config.ServerAddr))
		if err != nil {
			return nil, err
		}
		cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			return nil, err
		}
		server.TLSConfig.Certificates = append(server.TLSConfig.Certificates, cert)
		handler := server.Handler.(*http.ServeMux)
		if serversPerPort[s.config.ListenHTTPS] == 1 {
			handler.HandleFunc("/", s.handle)
		} else {
			handler.HandleFunc(fmt.Sprintf("%s/", serverURL.Hostname()), s.handle)
		}
	}
	serversList := make([]*http.Server, 0)
	for _, s := range servers {
		serversList = append(serversList, s)
	}
	return serversList, nil
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

var errInvalidNumberOfConfigs = errors.New("invalid number of configs, need at least one")
