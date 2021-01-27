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
	handler, err := createHandler(servers)
	if err != nil {
		return nil, err
	}
	return &ServerRouter{servers: servers, handler: handler}, nil
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
	r.srvHTTP, err = r.createHTTPServers(r.servers)
	if err != nil {
		return err
	}
	httpsServers, err := r.createHTTPSServerSpecs(r.servers)
	if err != nil {
		return err
	}

	log.Printf("%#v\n", r.srvHTTP)
	log.Printf("%#v\n", httpsServers)
	r.printListenInfo()

	errChan := make(chan error)
	for _, s := range r.srvHTTP {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil {
				errChan <- err
			}
		}(s)
	}
	for _, s := range httpsServers {
		go func(s *httpsServerSpec) {
			listener, err := tls.Listen("tcp", s.server.Addr, s.tlsConfig)
			if err != nil {
				errChan <- err
				return
			}
			if err := s.server.Serve(listener); err != nil {
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
	if r.servers[0].config.ListenHTTP != "" {
		listens = append(listens, fmt.Sprintf("%s/http", r.servers[0].config.ListenHTTP))
	}
	if r.servers[0].config.ListenHTTPS != "" {
		listens = append(listens, fmt.Sprintf("%s/https", r.servers[0].config.ListenHTTPS))
	}
	log.Printf("Listening on %s (%d clipboard(s))\n", strings.Join(listens, " "), len(r.servers))
}

type httpsServerSpec struct {
	server    *http.Server
	tlsConfig *tls.Config
}

func (r *ServerRouter) createHTTPSServerSpecs(servers []*Server) ([]*httpsServerSpec, error) {
	var ok bool
	var spec *httpsServerSpec
	listenSpecs := make(map[string]*httpsServerSpec, 0)
	for _, s := range servers {
		if s.config.ListenHTTPS == "" {
			continue
		}
		if spec, ok = listenSpecs[s.config.ListenHTTPS]; !ok {
			spec = &httpsServerSpec{
				server:    &http.Server{Addr: s.config.ListenHTTPS, Handler: http.NewServeMux()},
				tlsConfig: &tls.Config{Certificates: make([]tls.Certificate, 0)},
			}
			listenSpecs[s.config.ListenHTTPS] = spec
		}
		serverURL, err := url.ParseRequestURI(ExpandServerAddr(s.config.ServerAddr))
		if err != nil {
			return nil, err
		}
		handler := spec.server.Handler.(*http.ServeMux)
		handler.HandleFunc(fmt.Sprintf("%s/", serverURL.Hostname()), s.handle)

		cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			return nil, err
		}
		spec.tlsConfig.Certificates = append(spec.tlsConfig.Certificates, cert)
	}
	specs := make([]*httpsServerSpec, 0)
	for _, spec := range listenSpecs {
		specs = append(specs, spec)
	}
	return specs, nil
}

func (r *ServerRouter) createHTTPServers(servers []*Server) ([]*http.Server, error) {
	var ok bool
	var httpServer *http.Server
	listenHTTPServers := make(map[string]*http.Server, 0)
	for _, s := range servers {
		if s.config.ListenHTTP == "" {
			continue
		}
		if httpServer, ok = listenHTTPServers[s.config.ListenHTTP]; !ok {
			httpServer = &http.Server{Addr: s.config.ListenHTTP, Handler: http.NewServeMux()}
			listenHTTPServers[s.config.ListenHTTP] = httpServer
		}
		serverURL, err := url.ParseRequestURI(ExpandServerAddr(s.config.ServerAddr))
		if err != nil {
			return nil, err
		}
		handler := httpServer.Handler.(*http.ServeMux)
		handler.HandleFunc(fmt.Sprintf("%s/", serverURL.Hostname()), s.handle)
	}
	httpServers := make([]*http.Server, 0)
	for _, s := range listenHTTPServers {
		httpServers = append(httpServers, s)
	}
	return httpServers, nil
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

var errInvalidNumberOfConfigs = errors.New("invalid number of configs, need at least one")
