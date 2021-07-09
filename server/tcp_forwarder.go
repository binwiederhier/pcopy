package server

import (
	"fmt"
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
	pr, pw := io.Pipe()
	request, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/", s.UpstreamAddr), pr)
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

func (s *tcpForwarder) forwardRequest(conn net.Conn, upstreamWriter io.WriteCloser) error {
	buf := make([]byte, bufferSizeBytes)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.ReadTimeout)); err != nil {
			return fmt.Errorf("cannot set read deadline: %w", err)
		}
		read, err := conn.Read(buf)
		if err == io.EOF || (err != nil && strings.Contains(err.Error(), "i/o timeout")) { // poll.DeadlineExceededError is not accessible
			if read > 0 {
				if _, err := upstreamWriter.Write(buf[:read]); err != nil {
					return fmt.Errorf("error while writing to upstream: %w", err)
				}
			}
			return upstreamWriter.Close()
		} else if err != nil {
			upstreamWriter.Close() // closing the upstream request will finish ServeHTTP()
			return fmt.Errorf("cannot read from client: %w", err)
		}
		if _, err := upstreamWriter.Write(buf[:read]); err != nil {
			return fmt.Errorf("cannot write to upstream: %w", err)
		}
	}
}
