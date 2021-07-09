// Package server contains the pcopy server code. It contains a Server struct, which represents a single clipboard
// server, and a Router struct, which can be used to multiplex multiple clipboard servers onto the same port.
//
// To instantiate a new clipboard Server, use New using a well-defined Config:
//
//   server := server.New(config.New())
//   http.ListenAndServe(":9090", http.HandlerFunc(server.Handle))
//
// To use a Router, use NewRouter:
//
//   server1 := server.New(config1.New())
//   server2 := server.New(config2.New())
//   router := server.NewRouter(server1, server2)
//   router.Start()
//
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"heckel.io/pcopy/clipboard"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/util"
	htmltemplate "html/template"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"
)

const (
	// HeaderStream can be sent in PUT requests to enable streaming mode (default if not set: HeaderStreamDisabled)
	HeaderStream = "X-Stream"

	// HeaderStreamDisabled is a value for the X-Stream header that can be set to disable streaming mode (the default)
	HeaderStreamDisabled = "0"

	// HeaderStreamImmediateHeaders is a value for the X-Stream header that can be set to enable streaming, and to
	// immediately send response headers before the entire request body is consumed. This is non-standard HTTP and not
	// all clients support this.
	HeaderStreamImmediateHeaders = "1"

	// HeaderStreamDelayHeaders is a value for the X-Stream header that can be set to enable streaming mode, and to
	// delay sending response headers until the request body is fully consumed. If this is used with random file ID,
	// you'll need to use reserve a file name with X-Reserve first.
	HeaderStreamDelayHeaders = "2"

	// HeaderReserve can be sent in PUT requests to enable reservation mode
	HeaderReserve = "X-Reserve"

	// HeaderReserveEnabled is a value for X-Reserve that enabled reservation mode; no other values are possible
	HeaderReserveEnabled = "1"

	// HeaderNoRedirect prevents the redirect handler from redirecting to HTTPS
	HeaderNoRedirect = "X-No-Redirect"

	// HeaderFormat can be set in PUT requests to define the response format (default if not set: HeaderFormatText)
	HeaderFormat = "X-Format"

	// HeaderFormatText is a value for X-Format that will make PUT requests return human readable instructions for
	// how to retrieve a clipboard entry
	HeaderFormatText = "text"

	// HeaderFormatJSON is a value for X-Format that will format the HTTP response for PUT requests as JSON
	HeaderFormatJSON = "json"

	// HeaderFormatNone is a value for X-Format that will not return any response body. All values will only be sent in
	// HTTP response headers.
	HeaderFormatNone = "headersonly"

	// HeaderFileMode can be set in PUT requests to define whether a file should be read-only or read-write. Allowed
	// values are config.FileModeReadWrite and config.FileModeReadOnly.
	HeaderFileMode = "X-Mode"

	// HeaderFile is a response header containing the file name / identifier for the clipboard file
	HeaderFile = "X-File"

	// HeaderTTL is a response header containing the remaining time-to-live (TTL) for the clipboard file
	HeaderTTL = "X-TTL"

	// HeaderURL is a response header containing the full URL (including auth) to access the clipboard file
	HeaderURL = "X-URL"

	// HeaderExpires is a response header containing the file expiration unix timestamp for the clipboard file
	HeaderExpires = "X-Expires"

	// HeaderCurl is a response header containing the curl command that can be used to retrieve the clipboard file
	HeaderCurl = "X-Curl"

	queryParamAuth          = "a"
	queryParamStreamReserve = "r"
	queryParamStream        = "s"
	queryParamFormat        = "f"
	queryParamFileMode      = "m"
	queryParamTTL           = "t"
	queryParamDownload      = "d"
	queryParamFilename      = "f" // Same as format, but that's ok, since this is for GETs

	defaultMaxAuthAge   = time.Minute
	visitorExpungeAfter = 30 * time.Minute
	reserveTTL          = 10 * time.Second
	peakLimitBytes      = 512 * 1024
)

var (
	authHmacRegex       = regexp.MustCompile(`^HMAC (\d+) (\d+) (.+)$`)
	authBasicRegex      = regexp.MustCompile(`^Basic (\S+)$`)
	clipboardPathFormat = "/%s"
	templateFnMap       = template.FuncMap{
		"expandServerAddr": config.ExpandServerAddr,
		"encodeBase64":     base64.StdEncoding.EncodeToString,
		"bytesToHuman":     util.BytesToHuman,
		"durationToHuman":  util.DurationToHuman,
		"stringsJoin":      strings.Join,
		"htmlEscape":       htmltemplate.HTMLEscapeString,
	}

	//go:embed "index.gohtml"
	webTemplateSource string
	webTemplate       = template.Must(template.New("index").Funcs(templateFnMap).Parse(webTemplateSource))

	//go:embed "curl.tmpl"
	curlTemplateSource string
	curlTemplate       = template.Must(template.New("curl").Funcs(templateFnMap).Parse(curlTemplateSource))

	//go:embed static
	webStaticFs embed.FS
)

// Server is the main HTTP server struct. It's the one with all the good stuff.
type Server struct {
	config      *config.Config
	clipboard   *clipboard.Clipboard
	visitors    map[string]*visitor
	routes      []route
	managerChan chan bool
	mu          sync.Mutex
}

// File contains information about an uploaded file
type File struct {
	URL     string
	File    string
	TTL     time.Duration
	Expires time.Time
	Curl    string
}

// visitor represents an API user, and its associated rate.Limiter used for rate limiting
type visitor struct {
	limiterGET *rate.Limiter
	limiterPUT *rate.Limiter
	lastSeen   time.Time
}

// Info contains information about the server needed o join a server.
type Info struct {
	ServerAddr string            `json:"serverAddr"`
	DefaultID  string            `json:"defaultID"`
	Salt       []byte            `json:"salt"`
	Cert       *x509.Certificate `json:"-"`
}

// httpResponseFileInfo is the response returned when uploading a file
type httpResponseFileInfo struct {
	URL     string `json:"url"`
	File    string `json:"file"`
	TTL     int    `json:"ttl"`
	Expires int64  `json:"expires"`
	Curl    string `json:"curl"`
}

// handleFunc extends the normal http.HandlerFunc to be able to easily return errors
type handleFunc func(http.ResponseWriter, *http.Request) error

// route represents a HTTP route (e.g. GET /info), a regex that matches it and its handler
type route struct {
	method  string
	regex   *regexp.Regexp
	handler handleFunc
}

func newRoute(method, pattern string, handler handleFunc) route {
	return route{method, regexp.MustCompile("^" + pattern + "$"), handler}
}

// routeCtx is a marker struct used to find fields in route matches
type routeCtx struct{}

// webTemplateConfig is a struct defining all the things required to render the web root
type webTemplateConfig struct {
	KeyDerivIter int
	KeyLenBytes  int
	DefaultPort  int
	Config       *config.Config
}

// New creates a new instance of a Server using the given config. It does a few sanity checks to ensure
// the config will likely work.
func New(conf *config.Config) (*Server, error) {
	if conf.ListenHTTPS == "" && conf.ListenHTTP == "" {
		return nil, errListenAddrMissing
	}
	if conf.ListenHTTPS != "" {
		if conf.KeyFile == "" {
			return nil, errKeyFileMissing
		}
		if conf.CertFile == "" {
			return nil, errCertFileMissing
		}
	}
	clip, err := clipboard.New(conf)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:    conf,
		clipboard: clip,
		visitors:  make(map[string]*visitor),
		routes:    nil,
	}, nil
}

// Handle is the delegating handler function for a clipboard's server. It uses the routeList to find a matching route
// and delegates to it.
func (s *Server) Handle(w http.ResponseWriter, r *http.Request) {
	for _, route := range s.routeList() {
		matches := route.regex.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 && r.Method == route.method {
			log.Printf("[%s] %s - %s %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
			ctx := context.WithValue(r.Context(), routeCtx{}, matches[1:])
			if err := route.handler(w, r.WithContext(ctx)); err != nil {
				if err == clipboard.ErrInvalidFileID {
					s.fail(w, r, http.StatusBadRequest, err)
				} else if e, ok := err.(*ErrHTTP); ok {
					s.fail(w, r, e.Code, e)
				} else {
					s.fail(w, r, http.StatusInternalServerError, err)
				}
			}
			return
		}
	}
	if r.Method == http.MethodGet {
		s.fail(w, r, http.StatusNotFound, errNoMatchingRoute)
	} else {
		s.fail(w, r, http.StatusBadRequest, errNoMatchingRoute)
	}
}

func (s *Server) routeList() []route {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routes != nil {
		return s.routes
	}

	fileRoute := "/" + clipboard.FileRegexPart
	s.routes = []route{
		newRoute("GET", "/", s.limit(s.handleRoot)),
		newRoute("GET", "/curl", s.limit(s.handleCurlRoot)),
		newRoute("PUT", "/(random)?", s.limit(s.auth(s.handleClipboardPutRandom))),
		newRoute("POST", "/(random)?", s.limit(s.auth(s.handleClipboardPutRandom))),
		newRoute("GET", "/static/.+", s.limit(s.handleStatic)),
		newRoute("GET", "/favicon.ico", s.limit(s.handleFavicon)),
		newRoute("GET", "/info", s.limit(s.handleInfo)),
		newRoute("GET", "/verify", s.limit(s.auth(s.handleVerify))),
		newRoute("PUT", fileRoute, s.limit(s.authFile(s.handleClipboardPut))),
		newRoute("POST", fileRoute, s.limit(s.authFile(s.handleClipboardPut))),
		newRoute("GET", fileRoute, s.limit(s.authFile(s.handleClipboardGet))),
		newRoute("HEAD", fileRoute, s.limit(s.authFile(s.handleClipboardHead))),
	}
	return s.routes
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) error {
	log.Printf("[%s] %s - %s %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)

	var salt []byte
	if s.config.Key != nil {
		salt = s.config.Key.Salt
	}

	response := &Info{
		ServerAddr: s.config.ServerAddr,
		DefaultID:  s.config.DefaultID,
		Salt:       salt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	return json.NewEncoder(w).Encode(response)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) error {
	log.Printf("[%s] %s - %s %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
	return nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("User-Agent"), "curl/") {
		return s.handleCurlRoot(w, r)
	}
	return s.redirectHTTPS(s.handleWebRoot)(w, r)
}

func (s *Server) handleWebRoot(w http.ResponseWriter, r *http.Request) error {
	return webTemplate.Execute(w, &webTemplateConfig{
		KeyDerivIter: crypto.KeyDerivIter,
		KeyLenBytes:  crypto.KeyLenBytes,
		DefaultPort:  config.DefaultPort,
		Config:       s.config,
	})
}

func (s *Server) handleCurlRoot(w http.ResponseWriter, r *http.Request) error {
	return curlTemplate.Execute(w, &webTemplateConfig{Config: s.config})
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) error {
	r.URL.Path = "/static/img/favicon.ico"
	return s.handleStatic(w, r)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) error {
	http.FileServer(http.FS(webStaticFs)).ServeHTTP(w, r)
	return nil
}

func (s *Server) handleClipboardGet(w http.ResponseWriter, r *http.Request) error {
	fields := r.Context().Value(routeCtx{}).([]string)
	id := fields[0]
	download := false
	filename := id
	if r.URL.Query().Get(queryParamFilename) != "" {
		filename = r.URL.Query().Get(queryParamFilename)
	}
	if r.URL.Query().Get(queryParamDownload) == "1" {
		download = true
	}
	stat, err := s.clipboard.Stat(id)
	if err != nil {
		return ErrHTTPNotFound
	}
	if !stat.Pipe {
		w.Header().Set("Length", fmt.Sprintf("%d", stat.Size))
	}
	defer func() {
		if stat.Pipe {
			s.clipboard.DeleteFile(id)
		}
	}()
	return s.clipboard.ReadFile(id, util.NewContentTypeWriter(w, filename, download))
}

func (s *Server) handleClipboardHead(w http.ResponseWriter, r *http.Request) error {
	fields := r.Context().Value(routeCtx{}).([]string)
	id := fields[0]
	stat, err := s.clipboard.Stat(id)
	if err != nil {
		return ErrHTTPNotFound
	}
	if !stat.Pipe {
		w.Header().Set("Length", fmt.Sprintf("%d", stat.Size))
	}
	ttl := time.Until(time.Unix(stat.Expires, 0))
	if ttl < -1 {
		ttl = 0
	}
	return s.writeFileInfoOutput(w, id, stat.Expires, ttl, HeaderFormatNone, stat.Secret)
}

func (s *Server) handleClipboardPutRandom(w http.ResponseWriter, r *http.Request) error {
	ctx := context.WithValue(r.Context(), routeCtx{}, []string{randomFileID()})
	return s.handleClipboardPut(w, r.WithContext(ctx))
}

func (s *Server) handleClipboardPut(w http.ResponseWriter, r *http.Request) error {
	// Parse request: file ID, stream
	fields := r.Context().Value(routeCtx{}).([]string)
	id := fields[0]

	// Check if file exists
	if err := s.checkPUT(id, r.RemoteAddr); err != nil {
		return err
	}

	// Peak body, i.e. read up to 512 KB of the body into memory. This is needed two things:
	//
	// 1. Text-only TTL: to be able to determine if the body is UTF-8, we need to read it all. I have not figured
	//    out how to do this in a stream, so we only support long TTLs for short texts.
	// 2. Immediate headers (HeaderStreamImmediateHeaders): For very short POST payloads, "curl -d.." will
	//    (obviously) not send the "Expect: 100-continue" header, so the body is immediately consumed and closed
	//    by Go's HTTP server, yielding a http.ErrBodyReadAfterClose error. To counter this behavior in streaming mode,
	//    we consume the entire request body if it is short enough. In practice, curl will send "Expect: 100-continue"
	//    for anything > ~1400 bytes.
	body, err := util.Peak(r.Body, peakLimitBytes)
	if err != nil {
		return err
	}

	// Read query params & peak body
	format := s.getOutputFormat(r)
	reserve := s.isReserve(r)
	streamMode, err := s.getStreamMode(r)
	if err != nil {
		return err
	}
	fileMode, err := s.getFileMode(r)
	if err != nil {
		return err
	}
	ttl, err := s.getTTL(r, body)
	if err != nil {
		return err
	}
	expires := int64(0)
	if ttl > 0 {
		expires = time.Now().Add(ttl).Unix()
	}
	secret := ""
	if s.config.Key != nil {
		secret = randomSecret()
	}

	// Always delete file first to avoid awkward FIFO/regular-file behavior
	s.clipboard.DeleteFile(id)

	// Ensure that we update the limiters and such!
	defer s.updateStatsAndExpire()

	// For streaming mode a short-time reservation is necessary
	var meta *clipboard.File
	if reserve {
		meta = &clipboard.File{
			Mode:    config.FileModeReadWrite,
			Expires: time.Now().Add(reserveTTL).Unix(),
			Secret:  secret,
		}
	} else {
		meta = &clipboard.File{
			Mode:    fileMode,
			Expires: expires,
			Secret:  secret,
		}
	}

	// If this is a stream, make fifo device instead of file if type is set to "fifo".
	// Also, we want to immediately output instructions.
	if streamMode != HeaderStreamDisabled {
		if err := s.clipboard.MakePipe(id); err != nil {
			return err
		}
		if streamMode == HeaderStreamImmediateHeaders {
			// For this to work with curl, we have to have peaked the body for short payloads, since we're technically
			// writing a response before fully reading the body. See above when we peak the body.
			if err := s.writeFileInfoOutput(w, id, expires, ttl, format, secret); err != nil {
				return err
			}
		}
	}

	// Copy file contents (with file limit & total limit)
	if err := s.clipboard.WriteFile(id, meta, body); err != nil {
		if err == util.ErrLimitReached {
			return ErrHTTPPayloadTooLarge
		} else if err == clipboard.ErrBrokenPipe {
			// This happens when interrupting on receiver-side while streaming. We treat this as a success.
			return ErrHTTPPartialContent
		}
		return err
	}

	// Output URL, TTL, etc.
	if streamMode == HeaderStreamDisabled || streamMode == HeaderStreamDelayHeaders {
		if err := s.writeFileInfoOutput(w, id, expires, ttl, format, secret); err != nil {
			s.clipboard.DeleteFile(id)
			return err
		}
	}

	return nil
}

// checkPUT verifies that the PUT against the given ID is allowed
func (s *Server) checkPUT(id string, remoteAddr string) error {
	stat, _ := s.clipboard.Stat(id)
	if stat == nil {
		// TODO this should be in the WriteFile call
		// File does not exist, check total file count limit
		if !s.clipboard.Allow() {
			return ErrHTTPTooManyRequests
		}
	} else {
		// File exists, check if it can be overwritten
		m, err := s.clipboard.Stat(id)
		if err != nil {
			return err
		}
		if m.Mode != config.FileModeReadWrite {
			return ErrHTTPMethodNotAllowed
		}
	}
	return nil
}

func (s *Server) writeFileInfoOutput(w http.ResponseWriter, id string, expires int64, ttl time.Duration, format string, secret string) error {
	path := fmt.Sprintf(clipboardPathFormat, id)
	url, err := generateURL(s.config, path, secret)
	if err != nil {
		return err
	}
	curl, err := generateCurlCommand(s.config, url)
	if err != nil {
		curl = ""
	}

	w.Header().Set(HeaderURL, url)
	w.Header().Set(HeaderFile, id)
	w.Header().Set(HeaderTTL, fmt.Sprintf("%d", int(ttl.Seconds())))
	w.Header().Set(HeaderExpires, fmt.Sprintf("%d", expires))
	w.Header().Set(HeaderCurl, curl)

	if format == HeaderFormatJSON {
		response := &httpResponseFileInfo{
			URL:     url,
			File:    id,
			TTL:     int(ttl.Seconds()),
			Expires: expires,
			Curl:    curl,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return err
		}
	} else if format == HeaderFormatText {
		info := &File{
			URL:     url,
			File:    id,
			TTL:     ttl,
			Expires: time.Unix(expires, 0),
			Curl:    curl,
		}
		if _, err := w.Write([]byte(FileInfoInstructions(info))); err != nil {
			return err
		}
	}

	// This is important for streaming with curl, so that the download instructions
	// are immediately available before the request body is fully read.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	return nil
}

func (s *Server) getFileMode(r *http.Request) (string, error) {
	mode := s.config.FileModesAllowed[0]
	if r.Header.Get(HeaderFileMode) != "" {
		mode = r.Header.Get(HeaderFileMode)
	} else if r.URL.Query().Get(queryParamFileMode) != "" {
		mode = r.URL.Query().Get(queryParamFileMode)
	}
	for _, allowed := range s.config.FileModesAllowed {
		if mode == allowed {
			return mode, nil
		}
	}
	return "", ErrHTTPBadRequest
}

func (s *Server) getTTL(r *http.Request, peakedBody *util.PeakedReadCloser) (time.Duration, error) {
	var err error
	var ttl time.Duration

	// Get the TTL
	if r.URL.Query().Get(queryParamTTL) != "" {
		ttl, err = util.ParseDuration(r.URL.Query().Get(queryParamTTL))
	} else if r.Header.Get(HeaderTTL) != "" {
		ttl, err = util.ParseDuration(r.Header.Get(HeaderTTL))
	} else if s.config.FileExpireAfterDefault > 0 {
		ttl = s.config.FileExpireAfterDefault
	}
	if err != nil {
		return 0, ErrHTTPBadRequest
	}

	// If the given TTL is larger than the max allowed value, set it to the max value.
	// Special handling for text: if the body is a short text (as per our peaking), the text max value applies.
	// It may be a little inefficient to always check for UTF-8, but I think it's fine.
	if ttl > s.config.FileExpireAfterNonTextMax || ttl > s.config.FileExpireAfterTextMax {
		maxTTL := s.config.FileExpireAfterNonTextMax
		isShortText := !peakedBody.LimitReached && utf8.Valid(peakedBody.PeakedBytes)
		if isShortText {
			maxTTL = s.config.FileExpireAfterTextMax
		}
		if maxTTL > 0 && ttl > maxTTL {
			ttl = maxTTL
		}
	}

	return ttl, nil
}

func (s *Server) getStreamMode(r *http.Request) (string, error) {
	mode := HeaderStreamDisabled
	if r.URL.Query().Get(queryParamStream) != "" {
		mode = r.URL.Query().Get(queryParamStream)
	} else if r.Header.Get(HeaderStream) != "" {
		mode = r.Header.Get(HeaderStream)
	}
	if mode != HeaderStreamDisabled && mode != HeaderStreamImmediateHeaders && mode != HeaderStreamDelayHeaders {
		return "", errInvalidStreamMode
	}
	return mode, nil
}

func (s *Server) isReserve(r *http.Request) bool {
	return r.Header.Get(HeaderReserve) == HeaderReserveEnabled || r.URL.Query().Get(queryParamStreamReserve) == HeaderReserveEnabled
}

func (s *Server) getOutputFormat(r *http.Request) string {
	if r.Header.Get(HeaderFormat) == HeaderFormatJSON || r.URL.Query().Get(queryParamFormat) == HeaderFormatJSON {
		return HeaderFormatJSON
	} else if r.Header.Get(HeaderFormat) == HeaderFormatNone || r.URL.Query().Get(queryParamFormat) == HeaderFormatNone {
		return HeaderFormatNone
	}
	return HeaderFormatText
}

func (s *Server) auth(next handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := s.authorize(r); err != nil {
			return err
		}
		return next(w, r)
	}
}

func (s *Server) authFile(next handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := s.authorizeFileWithFallback(r); err != nil {
			return err
		}
		return next(w, r)
	}
}

func (s *Server) authorizeFileWithFallback(r *http.Request) error {
	fields := r.Context().Value(routeCtx{}).([]string)
	id := fields[0]
	stat, err := s.clipboard.Stat(id)
	if err != nil {
		return s.authorize(r)
	}
	if stat.Secret == "" {
		return s.authorize(r)
	}
	secret, ok := r.URL.Query()[queryParamAuth]
	if !ok || subtle.ConstantTimeCompare([]byte(stat.Secret), []byte(secret[0])) != 1 {
		return s.authorize(r)
	}
	return nil
}

func (s *Server) authorize(r *http.Request) error {
	if s.config.Key == nil {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if encodedQueryAuth, ok := r.URL.Query()[queryParamAuth]; ok && len(encodedQueryAuth) > 0 {
		queryAuth, err := base64.RawURLEncoding.DecodeString(encodedQueryAuth[0])
		if err != nil {
			log.Printf("[%s], %s - %s %s - cannot decode query auth override", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
			return ErrHTTPUnauthorized
		}
		auth = string(queryAuth)
	}

	if m := authHmacRegex.FindStringSubmatch(auth); m != nil {
		return s.authorizeHmac(r, m)
	} else if m := authBasicRegex.FindStringSubmatch(auth); m != nil {
		return s.authorizeBasic(r, m)
	} else {
		log.Printf("[%s] %s - %s %s - invalid or missing auth", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}
}

func (s *Server) authorizeHmac(r *http.Request, matches []string) error {
	timestamp, err := strconv.Atoi(matches[1])
	if err != nil {
		log.Printf("[%s] %s - %s %s - hmac timestamp conversion: %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	ttlSecs, err := strconv.Atoi(matches[2])
	if err != nil {
		log.Printf("[%s] %s - %s %s - hmac ttl conversion: %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	hash, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		log.Printf("[%s] %s - %s %s - hmac base64 conversion: %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	// Recalculate HMAC
	// TODO this should include the query string
	data := []byte(fmt.Sprintf("%d:%d:%s:%s", timestamp, ttlSecs, r.Method, r.URL.Path))
	hm := hmac.New(sha256.New, s.config.Key.Bytes)
	if _, err := hm.Write(data); err != nil {
		log.Printf("[%s] %s - %s %s - hmac calculation: %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}
	rehash := hm.Sum(nil)

	// Compare HMAC in constant time (to prevent timing attacks)
	if subtle.ConstantTimeCompare(hash, rehash) != 1 {
		log.Printf("[%s] %s - %s %s - hmac invalid", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}

	// Compare timestamp (to prevent replay attacks)
	maxAge := defaultMaxAuthAge
	if ttlSecs > 0 {
		maxAge = time.Second * time.Duration(ttlSecs)
	}
	if maxAge > 0 {
		age := time.Since(time.Unix(int64(timestamp), 0))
		if age > maxAge {
			log.Printf("[%s] %s - %s %s - hmac request age mismatch", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
			return ErrHTTPUnauthorized
		}
	}

	return nil
}

func (s *Server) authorizeBasic(r *http.Request, matches []string) error {
	userPassBytes, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		log.Printf("[%s] %s - %s %s - basic base64 conversion: %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	userPassParts := strings.Split(string(userPassBytes), ":")
	if len(userPassParts) != 2 {
		log.Printf("[%s] %s - %s %s - basic invalid user/pass format", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}
	passwordBytes := []byte(userPassParts[1])

	// Compare HMAC in constant time (to prevent timing attacks)
	key := crypto.DeriveKey(passwordBytes, s.config.Key.Salt)
	if subtle.ConstantTimeCompare(key.Bytes, s.config.Key.Bytes) != 1 {
		log.Printf("[%s] %s - %s %s - basic invalid", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}

	return nil
}

// startManager will start the server manager background process that will update the stats and expire
// files for which the TTL has been reached. This method exits immediately and will spin up a goroutine.
func (s *Server) startManager() {
	s.mu.Lock()
	if s.managerChan != nil {
		s.mu.Unlock()
		return
	}
	s.managerChan = make(chan bool)
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(s.config.ManagerInterval)
		for {
			s.updateStatsAndExpire()
			select {
			case <-ticker.C:
			case <-s.managerChan:
				s.mu.Lock()
				s.managerChan = nil
				s.mu.Unlock()
				return
			}
		}
	}()
}

// stopManager will stop the existing manager goroutine if one is running.
func (s *Server) stopManager() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.managerChan != nil {
		close(s.managerChan)
	}
}

func (s *Server) updateStatsAndExpire() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Expire visitors from rate visitors map
	for ip, v := range s.visitors {
		if time.Since(v.lastSeen) > visitorExpungeAfter {
			delete(s.visitors, ip)
		}
	}

	// Walk clipboard to update size/count limiters, and expire/delete files
	if err := s.clipboard.Expire(); err != nil {
		log.Printf("[%s] cannot expire clipboard entries: %s", config.CollapseServerAddr(s.config.ServerAddr), err.Error())
	}

	stats, err := s.clipboard.Stats()
	if err != nil {
		log.Printf("[%s] cannot get stats from clipboard: %s", config.CollapseServerAddr(s.config.ServerAddr), err.Error())
	} else {
		s.printStats(stats)
	}
}

func (s *Server) printStats(stats *clipboard.Stats) {
	var countLimit, sizeLimit string
	if s.config.ClipboardCountLimit == 0 {
		countLimit = "no limit"
	} else {
		countLimit = fmt.Sprintf("max %d", s.config.ClipboardCountLimit)
	}
	if s.config.ClipboardSizeLimit == 0 {
		sizeLimit = "no limit"
	} else {
		sizeLimit = fmt.Sprintf("max %s", util.BytesToHuman(s.config.ClipboardSizeLimit))
	}
	log.Printf("[%s] files: %d (%s), size: %s (%s), visitors: %d (last 30 minutes)",
		config.CollapseServerAddr(s.config.ServerAddr), stats.Count, countLimit, util.BytesToHuman(stats.Size), sizeLimit, len(s.visitors))
}

func (s *Server) redirectHTTPS(next handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get(HeaderNoRedirect) == "" && r.TLS == nil && s.config.ListenHTTPS != "" {
			newURL := r.URL
			newURL.Host = r.Host
			newURL.Scheme = "https"
			if strings.Contains(newURL.Host, ":") {
				newURL.Host, _, _ = net.SplitHostPort(newURL.Host)
			}
			_, port, _ := net.SplitHostPort(s.config.ListenHTTPS)
			if port != "443" {
				newURL.Host = net.JoinHostPort(newURL.Host, port)
			}
			http.Redirect(w, r, newURL.String(), http.StatusFound)
			return nil
		}
		return next(w, r)
	}
}

// limit wraps all HTTP endpoints and limits API use to a certain number of requests per second.
// This function was taken from https://www.alexedwards.net/blog/how-to-rate-limit-http-requests (MIT).
func (s *Server) limit(next handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		v := s.getVisitor(r.RemoteAddr)
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if !v.limiterGET.Allow() {
				return ErrHTTPTooManyRequests
			}
		} else {
			if !v.limiterPUT.Allow() {
				return ErrHTTPTooManyRequests
			}
		}

		return next(w, r)
	}
}

// getVisitor creates or retrieves a rate.Limiter for the given visitor.
// This function was taken from https://www.alexedwards.net/blog/how-to-rate-limit-http-requests (MIT).
func (s *Server) getVisitor(remoteAddr string) *visitor {
	s.mu.Lock()
	defer s.mu.Unlock()

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr // This should not happen in real life; only in tests.
	}

	v, exists := s.visitors[ip]
	if !exists {
		v = &visitor{
			rate.NewLimiter(s.config.LimitGET, s.config.LimitGETBurst),
			rate.NewLimiter(s.config.LimitPUT, s.config.LimitPUTBurst),
			time.Now(),
		}
		s.visitors[ip] = v
		return v
	}

	v.lastSeen = time.Now()
	return v
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("[%s] %s - %s %s - %s", config.CollapseServerAddr(s.config.ServerAddr), r.RemoteAddr, r.Method, r.RequestURI, err.Error())
	w.WriteHeader(code)
	w.Write([]byte(http.StatusText(code)))
}
