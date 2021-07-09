package main

import (
	"io"
	"log"
	"net"
	"time"
)

func main() {
	s := &TCPForwarder{Addr: ":1234", ReadTimeout: 2 * time.Second}
	s.ListenAndServe()
}

const (
	defaultReadTimeout = 3 * time.Second
	bufferSizeBytes = 16 * 1024
)

type TCPForwarder struct {
	Addr   string
	ReadTimeout time.Duration
}

func NewTCPForwarder(addr string) *TCPForwarder {
	return &TCPForwarder{
		Addr: addr,
		ReadTimeout: defaultReadTimeout,
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
		go s.handleConn(conn)
	}
}

func (s *TCPForwarder) handleConn(conn net.Conn) {
	defer conn.Close()
	defer println("done handleConn")

	buf := make([]byte, bufferSizeBytes)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.ReadTimeout)); err != nil {
			log.Printf("cannot set read deadline on connection: %s", err.Error())
			return
		}
		read, err := conn.Read(buf)
		if err == io.EOF {
			if read > 0 {
				println("read: " + string(buf[:read]))
			}
			return
		} else if err != nil {
			log.Printf("error reading from connection: %s", err.Error())
			return
		}
		println("read: " + string(buf[:read]))
	}
}
