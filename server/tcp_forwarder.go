package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"heckel.io/pcopy/util"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultReadTimeout = 3 * time.Second // min upload speed: 16KB / 3s = 5KB/s
	bufferSizeBytes    = 16 * 1024
)

// tcpForwarder is a server that listens on a raw TCP socket and forwards incoming connections to an upstream
// HTTP handler function as a PUT request. That makes it possible to do "cat ... | nc nopaste.net 9999".
type tcpForwarder struct {
	Addr            string
	UpstreamAddr    string
	UpstreamHandler http.HandlerFunc
	ReadTimeout     time.Duration
	cancel          context.CancelFunc
	mu              sync.Mutex
}

func newTCPForwarder(addr string, upstreamAddr string, upstreamHandler http.HandlerFunc) *tcpForwarder {
	return &tcpForwarder{
		Addr:            addr,
		UpstreamAddr:    upstreamAddr,
		UpstreamHandler: upstreamHandler,
		ReadTimeout:     defaultReadTimeout,
	}
}

// listenAndServe listens on the configured TCP address and delegates incoming connections to handleConn
// in a new goroutine. This function does not return unless there is an error or until shutdown is called.
func (s *tcpForwarder) listenAndServe() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("error accepting connection on %s: %s", s.Addr, err.Error())
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if err := s.handleConn(conn); err != nil {
					io.WriteString(conn, fmt.Sprintf("%s\n", err.Error())) // might fail
					log.Printf("%s - tcp forward error: %s", conn.RemoteAddr().String(), err.Error())
				}
			}(conn)
		}
	}()

	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	<-ctx.Done()
	return nil
}

// shutdown cancels the listenAndServe function gracefully
func (s *tcpForwarder) shutdown() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
}

// handleConn reads from the TCP socket and forwards it to the HTTP handler. This method does NOT close the underlying
// connection. This is done in listenAndServe to ensure that error messages (if any) can be sent to the client.
func (s *tcpForwarder) handleConn(conn net.Conn) error {
	// Peak connection to detect "pcopy:..." prefix and extract path
	connReadCloser := &connTimeoutReadCloser{conn: conn, timeout: s.ReadTimeout}
	peaked, err := util.Peak(connReadCloser, bufferSizeBytes)
	if err != nil {
		return fmt.Errorf("cannot peak: %w", err)
	} else if strings.TrimSpace(string(peaked.PeakedBytes)) == "help" || strings.TrimSpace(string(peaked.PeakedBytes)) == "" {
		return s.handleHelp(conn)
	}
	path, offset := extractPath(peaked.PeakedBytes)

	// Forward upstream HTTP request to UpstreamHandler and response to downstream conn
	rawURL := fmt.Sprintf("%s/%s", s.UpstreamAddr, path)
	requestBody := io.MultiReader(bytes.NewReader(peaked.PeakedBytes[offset:]), connReadCloser)
	request, err := http.NewRequest(http.MethodPut, rawURL, requestBody)
	if err != nil {
		return fmt.Errorf("cannot create forwarding request: %w", err)
	}
	request.RequestURI = fmt.Sprintf("/%s", path)
	request.RemoteAddr = conn.RemoteAddr().String()
	request.Header.Set(HeaderNoRedirect, "1")
	s.UpstreamHandler.ServeHTTP(newTCPResponseWriter(conn), request)
	return nil
}

// handleHelp writes the netcat help page to the connection and exits; it does this
// by forwarding the request to the upstream /nc page.
func (s *tcpForwarder) handleHelp(conn net.Conn) error {
	rawURL := fmt.Sprintf("%s/nc", s.UpstreamAddr)
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("cannot create forwarding request: %w", err)
	}
	request.RequestURI = "/nc"
	request.RemoteAddr = conn.RemoteAddr().String()
	request.Header.Set(HeaderNoRedirect, "1")
	s.UpstreamHandler.ServeHTTP(newTCPResponseWriter(conn), request)
	return nil
}

// extractPath reads the path from the peaked bytes if the bytes start with "pcopy:" and returns the
// extracted path and the offset of the actual payload. An input of "pcopy:abc?a=123\npayload" will
// yield ("abc?a=123", 16). If there is no "pcopy:" prefix, then ("", 0) will be returned.
func extractPath(peaked []byte) (string, int) {
	reader := bufio.NewReader(bytes.NewReader(peaked))
	s, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(s, "pcopy:") {
		return "", 0
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "pcopy:"), "\n"), len(s)
}

// connTimeoutReadCloser implements an io.ReadCloser that will call SetReadDeadline before
// every Read and will return io.EOF if a Read times out.
type connTimeoutReadCloser struct {
	conn    net.Conn
	timeout time.Duration
	lastErr error
}

func (c *connTimeoutReadCloser) Read(p []byte) (n int, err error) {
	if c.lastErr == io.EOF {
		return 0, io.EOF // No need to wait if we're at the end
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, fmt.Errorf("cannot set read deadline: %w", err)
	}
	read, err := c.conn.Read(p)
	if err != nil && strings.Contains(err.Error(), "i/o timeout") { // poll.DeadlineExceededError is not accessible
		err = io.EOF
	}
	c.lastErr = err
	return read, err
}

func (c *connTimeoutReadCloser) Close() error {
	return c.conn.Close()
}

// tcpResponseWriter implements a http.ResponseWriter that only passes the body through to the
// underlying io.Writer and ignores all headers and the status code.
type tcpResponseWriter struct {
	underlying io.Writer
	header     http.Header
}

func newTCPResponseWriter(underlying io.Writer) *tcpResponseWriter {
	return &tcpResponseWriter{
		underlying: underlying,
		header:     http.Header{},
	}
}

func (s *tcpResponseWriter) Header() http.Header {
	return s.header
}

func (s *tcpResponseWriter) Write(b []byte) (int, error) {
	return s.underlying.Write(b)
}

func (s *tcpResponseWriter) WriteHeader(statusCode int) {
	// We don't care about the status code
}
