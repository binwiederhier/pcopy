package server

import (
	"bufio"
	"bytes"
	"fmt"
	"heckel.io/pcopy/util"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

const (
	defaultReadTimeout = 3 * time.Second
	bufferSizeBytes    = 16 * 1024
)

// tcpForwarder is a server that listens on a raw TCP socket and forwards incoming connections to an upstream
// HTTP handler function as a PUT request. That makes it possible to do "cat ... | nc nopaste.net 9999".
type tcpForwarder struct {
	Addr            string
	UpstreamAddr    string
	UpstreamHandler http.HandlerFunc
	ReadTimeout     time.Duration
}

func newTCPForwarder(addr string, upstreamAddr string, upstreamHandler http.HandlerFunc) *tcpForwarder {
	return &tcpForwarder{
		Addr:            addr,
		UpstreamAddr:    upstreamAddr,
		UpstreamHandler: upstreamHandler,
		ReadTimeout:     defaultReadTimeout,
	}
}

func (s *tcpForwarder) listenAndServe() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("error accepting connection on %s: %s", s.Addr, err.Error())
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			if err := s.handleConn(conn); err != nil {
				io.WriteString(conn, err.Error()) // might fail
				log.Printf("%s - tcp forward error: %s", conn.RemoteAddr().String(), err.Error())
			}
		}(conn)
	}
}

// handleConn reads from the TCP socket and forwards it to the HTTP handler. This method does NOT close the underlying
// connection. This is done in the listenAndServe to ensure that error messages can be sent to the client.
func (s *tcpForwarder) handleConn(conn net.Conn) error {
	//connReadCloser := &connTimeoutReadCloser{conn: conn, timeout: s.ReadTimeout}
	if err := conn.SetReadDeadline(time.Now().Add(s.ReadTimeout)); err != nil {
		return fmt.Errorf("cannot set read deadline: %w", err)
	}
	peaked, err := util.Peak(conn, bufferSizeBytes)
	if err != nil {
		return fmt.Errorf("cannot peak: %w", err)
	}
	path, offset := extractPath(peaked.PeakedBytes)

	pr, pw := io.Pipe()
	body := io.MultiReader(bytes.NewReader(peaked.PeakedBytes[offset:]), pr)
	request, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/%s", s.UpstreamAddr, path), body)
	if err != nil {
		return fmt.Errorf("cannot create forwarding request: %w", err)
	}
	request.RemoteAddr = conn.RemoteAddr().String()
	request.Header.Set(HeaderNoRedirect, "1")

	errChan := make(chan error)
	go func() {
		errChan <- s.forwardRequest(conn, pw)
	}()

	rr := httptest.NewRecorder()
	s.UpstreamHandler.ServeHTTP(rr, request)
	if err := <-errChan; err != nil {
		return err
	}
	if _, err := conn.Write(rr.Body.Bytes()); err != nil {
		return err
	}
	return nil
}

func extractPath(peaked []byte) (string, int) {
	reader := bufio.NewReader(bytes.NewReader(peaked))
	s, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(s, "pcopy:") {
		return "", 0
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "pcopy:"), "\n"), len(s)
}

func (s *tcpForwarder) forwardRequest(conn net.Conn, upstreamWriter io.WriteCloser) error {
	buf := make([]byte, bufferSizeBytes)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.ReadTimeout)); err != nil {
			return fmt.Errorf("cannot set read deadline: %w", err)
		}
		read, err := conn.Read(buf)
		isEOF := err == io.EOF || (err != nil && strings.Contains(err.Error(), "i/o timeout")) // poll.DeadlineExceededError is not accessible
		if err != nil && !isEOF {
			upstreamWriter.Close() // closing the upstream request will finish ServeHTTP()
			return fmt.Errorf("cannot read from client: %w", err)
		}
		if read > 0 {
			if _, err := upstreamWriter.Write(buf[:read]); err != nil {
				return fmt.Errorf("cannot write to upstream: %w", err)
			}
		}
		if isEOF {
			return upstreamWriter.Close()
		}
	}
}

type connTimeoutReadCloser struct {
	conn    net.Conn
	timeout time.Duration
}

func (c *connTimeoutReadCloser) Read(p []byte) (n int, err error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, fmt.Errorf("cannot set read deadline: %w", err)
	}
	read, err := c.conn.Read(p)
	if err != nil && strings.Contains(err.Error(), "i/o timeout") { // poll.DeadlineExceededError is not accessible
		err = io.EOF
	}
	return read, err
}

func (c *connTimeoutReadCloser) Close() error {
	return c.conn.Close()
}
