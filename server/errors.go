package server

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrHTTP is a generic HTTP error for any non-200 HTTP error
type ErrHTTP struct {
	Code   int
	Status string
}

func (e ErrHTTP) Error() string {
	return fmt.Sprintf("http: %s", e.Status)
}

// ErrHTTPPartialContent is returned when the client interrupts a stream and only partial content was sent
var ErrHTTPPartialContent = &ErrHTTP{http.StatusPartialContent, http.StatusText(http.StatusPartialContent)}

// ErrHTTPBadRequest is returned when the request sent by the client was invalid, e.g. invalid file name
var ErrHTTPBadRequest = &ErrHTTP{http.StatusBadRequest, http.StatusText(http.StatusBadRequest)}

// ErrHTTPMethodNotAllowed is returned when the file state does not allow the current method, e.g. PUTting a read-only file
var ErrHTTPMethodNotAllowed = &ErrHTTP{http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed)}

// ErrHTTPNotFound is returned when a resource is not found on the server
var ErrHTTPNotFound = &ErrHTTP{http.StatusNotFound, http.StatusText(http.StatusNotFound)}

// ErrHTTPTooManyRequests is returned when a server-side rate limit has been reached
var ErrHTTPTooManyRequests = &ErrHTTP{http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests)}

// ErrHTTPPayloadTooLarge is returned when the clipboard/file-size limit has been reached
var ErrHTTPPayloadTooLarge = &ErrHTTP{http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge)}

// ErrHTTPUnauthorized is returned when the client has not sent proper credentials
var ErrHTTPUnauthorized = &ErrHTTP{http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)}

var errListenAddrMissing = errors.New("listen address missing, add 'ListenHTTPS' or 'ListenHTTP' to config or pass --listen-http(s)")
var errKeyFileMissing = errors.New("private key file missing, add 'KeyFile' to config or pass --keyfile")
var errCertFileMissing = errors.New("certificate file missing, add 'CertFile' to config or pass --certfile")
var errInvalidStreamMode = errors.New("invalid stream mode")
var errNoMatchingRoute = errors.New("no matching route")
