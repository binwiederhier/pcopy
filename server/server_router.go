package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"heckel.io/pcopy/config"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Router is a simple vhost delegator to be able to run multiple clipboards on the same port.
// It runs the actual HTTP(S) servers and delegates based on the configured hostname.
type Router struct {
	servers       []*Server
	httpServers   []*http.Server
	tcpForwarders []*tcpForwarder
	mu            sync.Mutex
}

// Serve starts a server and listens for incoming HTTPS requests. The server handles all management operations (info,
// verify, ...), as well as the actual clipboard functionality (GET/PUT/POST). It also starts a background process
// to prune old.
//
// The function supports many configs, multiplexing based on the HTTP "Host:" header to the individual Server instances.
// If more than one config is passed, the "ListenAddr" configuration setting must be identical for all of them.
func Serve(configs ...*config.Config) error {
	router, err := NewRouter(configs...)
	if err != nil {
		return err
	}
	return router.Start()
}

// NewRouter creates a new multi-clipboard server using the given configs.
//
// The function supports many configs, multiplexing based on the HTTP "Host:" header to the individual Server instances.
// If more than one config is passed, the "ListenAddr" configuration setting must be identical for all of them.
func NewRouter(configs ...*config.Config) (*Router, error) {
	var err error
	if len(configs) == 0 {
		return nil, errInvalidNumberOfConfigs
	}
	servers, err := createServers(configs)
	if err != nil {
		return nil, err
	}
	return &Router{servers: servers}, nil
}

// Start starts the HTTP(S) server
func (r *Router) Start() error {
	r.mu.Lock()

	var err error
	r.httpServers, err = r.createHTTPServers()
	if err != nil {
		return err
	}
	r.tcpForwarders, err = r.createTCPForwarders()
	if err != nil {
		return err
	}
	r.printListenInfo()

	errChan := make(chan error)
	for _, s := range r.httpServers {
		go func(s *http.Server) {
			if s.TLSConfig != nil {
				listener, err := tls.Listen("tcp", s.Addr, s.TLSConfig)
				if err != nil {
					errChan <- err
					return
				}
				if err := s.Serve(listener); err != nil {
					errChan <- err
				}
			} else {
				if err := s.ListenAndServe(); err != nil {
					errChan <- err
				}
			}
		}(s)
	}
	for _, s := range r.tcpForwarders {
		go func(s *tcpForwarder) {
			if err := s.listenAndServe(); err != nil {
				errChan <- err
			}
		}(s)
	}

	for _, s := range r.servers {
		s.startManager()
	}

	r.mu.Unlock()
	err = <-errChan
	return err
}

// Stop immediately shuts down the HTTP(S) server. This is not a graceful shutdown.
func (r *Router) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.httpServers != nil {
		for _, s := range r.httpServers {
			if err := s.Close(); err != nil {
				return err
			}
		}
	}
	if r.tcpForwarders != nil {
		for _, s := range r.tcpForwarders {
			s.shutdown()
		}
	}
	for _, s := range r.servers {
		s.stopManager()
	}
	r.httpServers = nil
	return nil
}

func createServers(configs []*config.Config) ([]*Server, error) {
	servers := make([]*Server, len(configs))
	for i, conf := range configs {
		var err error
		servers[i], err = New(conf)
		if err != nil {
			return nil, err
		}
	}
	return servers, nil
}

func (r *Router) printListenInfo() {
	listens := make([]string, 0)
	for _, s := range r.httpServers {
		proto := "http"
		if s.TLSConfig != nil {
			proto = "https"
		}
		listens = append(listens, fmt.Sprintf("%s/%s", s.Addr, proto))
	}
	for _, s := range r.tcpForwarders {
		listens = append(listens, fmt.Sprintf("%s/tcp", s.Addr))
	}
	log.Printf("Listening on %s (%d clipboard(s))\n", strings.Join(listens, " "), len(r.servers))
}

func (r *Router) createHTTPServers() ([]*http.Server, error) {
	serversPerPort := make(map[string]int)
	for _, s := range r.servers {
		serversPerPort[s.config.ListenHTTP]++
		serversPerPort[s.config.ListenHTTPS]++
	}
	servers := make(map[string]*http.Server)
	for _, s := range r.servers {
		if s.config.ListenHTTP != "" {
			if _, err := r.createServerOrAddHandler(servers, serversPerPort, s, s.config.ListenHTTP); err != nil {
				return nil, err
			}
		}
		if s.config.ListenHTTPS != "" {
			server, err := r.createServerOrAddHandler(servers, serversPerPort, s, s.config.ListenHTTPS)
			if err != nil {
				return nil, err
			}
			cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
			if err != nil {
				return nil, err
			}
			if server.TLSConfig == nil {
				server.TLSConfig = &tls.Config{Certificates: make([]tls.Certificate, 0)}
			}
			server.TLSConfig.Certificates = append(server.TLSConfig.Certificates, cert)
		}
	}
	serversList := make([]*http.Server, 0)
	for _, s := range servers {
		serversList = append(serversList, s)
	}
	return serversList, nil
}

func (r *Router) createServerOrAddHandler(servers map[string]*http.Server, serversPerPort map[string]int, s *Server, listen string) (*http.Server, error) {
	server, ok := servers[listen]
	if !ok {
		server = &http.Server{Addr: listen, Handler: http.NewServeMux()}
		servers[listen] = server
	}
	serverURL, err := url.ParseRequestURI(config.ExpandServerAddr(s.config.ServerAddr))
	if err != nil {
		return nil, err
	}
	handler := server.Handler.(*http.ServeMux)
	if serversPerPort[listen] == 1 {
		handler.HandleFunc("/", s.Handle)
	} else {
		handler.HandleFunc(fmt.Sprintf("%s/", serverURL.Hostname()), s.Handle)
	}
	return server, nil
}

func (r *Router) createTCPForwarders() ([]*tcpForwarder, error) {
	servers := make([]*tcpForwarder, 0)
	for _, s := range r.servers {
		if s.config.ListenTCP != "" {
			server := newTCPForwarder(s.config.ListenTCP, config.ExpandServerAddr(s.config.ServerAddr), s.Handle)
			servers = append(servers, server)
		}
	}
	return servers, nil
}

var errInvalidNumberOfConfigs = errors.New("invalid number of configs, need at least one")
