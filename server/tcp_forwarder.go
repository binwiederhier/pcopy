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

type TCPForwarder struct {
	Addr            string
	UpstreamAddr    string
	UpstreamHandler http.HandlerFunc
	ReadTimeout     time.Duration
}

func NewTCPForwarder(addr string, upstreamAddr string, upstreamHandler http.HandlerFunc) *TCPForwarder {
	return &TCPForwarder{
		Addr:            addr,
		UpstreamAddr:    upstreamAddr,
		UpstreamHandler: upstreamHandler,
		ReadTimeout:     defaultReadTimeout,
	}
}

func (s *TCPForwarder) ListenAndServe() error {
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
				log.Printf("error in connection %s: %s", conn.RemoteAddr().String(), err.Error())
			}
		}(conn)
	}
}

func (s *TCPForwarder) handleConn(conn net.Conn) error {
	defer conn.Close()

	pr, pw := io.Pipe()
	request, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/", s.UpstreamAddr), pr)
	if err != nil {
		return fmt.Errorf("cannot create forwarding request: %w", err)
	}
	request.RemoteAddr = conn.RemoteAddr().String()
	request.Header.Set(HeaderFormat, HeaderFormatText)

	errChan := make(chan error)
	go func() {
		errChan <- s.translateRequest(conn, pw)
	}()

	rr := &httptest.ResponseRecorder{}
	s.UpstreamHandler.ServeHTTP(rr, request)
	println("done serve")
	if err := <-errChan; err != nil {
		return err
	}
	log.Printf("rr: %#v\n", rr)
	if rr.Body == nil {
		return fmt.Errorf("unexpected response from upstream; body is empty")
	}
	if _, err := conn.Write(rr.Body.Bytes()); err != nil {
		return err
	}
	return nil
}

func (s *TCPForwarder) translateRequest(conn net.Conn, upstreamWriter io.WriteCloser) error {
	buf := make([]byte, bufferSizeBytes)
	for {
		log.Printf("next read")
		if err := conn.SetReadDeadline(time.Now().Add(s.ReadTimeout)); err != nil {
			return fmt.Errorf("cannot set read deadline: %w", err)
		}
		read, err := conn.Read(buf)
		if err == io.EOF || (err != nil && strings.Contains(err.Error(), "i/o timeout")) { // poll.DeadlineExceededError is not accessible
			if read > 0 {
				log.Printf("read: %#v", buf[:read])
				if _, err := upstreamWriter.Write(buf[:read]); err != nil {
					return fmt.Errorf("error while writing to upstream: %w", err)
				}
			}
			return upstreamWriter.Close()
		} else if err != nil {
			log.Printf("err: %#v", err.Error())
			return fmt.Errorf("error reading from connection: %w", err)
		}
		log.Printf("read: %#v", buf[:read])
		if _, err := upstreamWriter.Write(buf[:read]); err != nil {
			return fmt.Errorf("error while writing to upstream: %w", err)
		}
	}
}
