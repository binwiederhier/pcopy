package pcopy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

const (
	managerTickerInterval         = 30 * time.Second
	defaultMaxAuthAge             = time.Minute
	noAuthRequestAge              = 0
	visitorRequestsPerSecond      = 2
	visitorRequestsPerSecondBurst = 5
	visitorExpungeAfter           = 3 * time.Minute
	certCommonName                = "pcopy"
	reserveTTL                    = 10 * time.Second

	headerStream            = "X-Stream"
	headerReserve           = "X-Reserve"
	headerFormat            = "X-Format"
	headerFileMode          = "X-Mode"
	headerFile              = "X-File"
	headerTTL               = "X-TTL"
	headerURL               = "X-URL"
	headerExpires           = "X-Expires"
	headerCurl              = "X-Curl"
	queryParamAuth          = "a"
	queryParamStreamReserve = "r"
	queryParamStream        = "s"
	queryParamFormat        = "f"
	queryParamFileMode      = "m"
	queryParamTTL           = "t"

	formatJSON        = "json"
	formatText        = "text"
	formatHeadersOnly = "headersonly"

	streamModeNoStream         = "0"
	streamModeImmediateHeaders = "1"
	streamModeDelayHeaders     = "2"
)

var (
	authHmacFormat      = "HMAC %d %d %s" // timestamp ttl b64-hmac
	authHmacRegex       = regexp.MustCompile(`^HMAC (\d+) (\d+) (.+)$`)
	authBasicRegex      = regexp.MustCompile(`^Basic (\S+)$`)
	clipboardPathFormat = "/%s"

	//go:embed "web/index.gohtml"
	webTemplateSource string
	webTemplate       = template.Must(template.New("index").Funcs(templateFnMap).Parse(webTemplateSource))

	//go:embed "web/curl.tmpl"
	curlTemplateSource string
	curlTemplate       = template.Must(template.New("curl").Funcs(templateFnMap).Parse(curlTemplateSource))

	//go:embed web/static
	webStaticFs embed.FS
)

// Server is the main HTTP server struct. It's the one with all the good stuff.
type Server struct {
	config    *Config
	clipboard *clipboard
	visitors  map[string]*visitor
	routes    []route
	sync.Mutex
}

// visitor represents an API user, and its associated rate.Limiter used for rate limiting
type visitor struct {
	countLimiter *limiter
	rateLimiter  *rate.Limiter
	lastSeen     time.Time
}

// httpResponseServerInfo is the response returned by the /info endpoint
type httpResponseServerInfo struct {
	ServerAddr string `json:"serverAddr"`
	Salt       string `json:"salt"`
}

// httpResponseFileInfo is the response returned when uploading a file
type httpResponseFileInfo struct {
	URL     string `json:"url"`
	File    string `json:"file"`
	TTL     int    `json:"ttl"`
	Expires int64  `json:"expires"`
	Curl    string `json:"curl"`
}

// handlerFnWithErr extends the normal http.HandlerFunc to be able to easily return errors
type handlerFnWithErr func(http.ResponseWriter, *http.Request) error

// route represents a HTTP route (e.g. GET /info), a regex that matches it and its handler
type route struct {
	method  string
	regex   *regexp.Regexp
	handler handlerFnWithErr
}

func newRoute(method, pattern string, handler handlerFnWithErr) route {
	return route{method, regexp.MustCompile("^" + pattern + "$"), handler}
}

// routeCtx is a marker struct used to find fields in route matches
type routeCtx struct{}

// webTemplateConfig is a struct defining all the things required to render the web root
type webTemplateConfig struct {
	KeyDerivIter int
	KeyLenBytes  int
	DefaultPort  int
	Config       *Config
}

// NewServer creates a new instance of a Server using the given config. It does a few sanity checks to ensure
// the config will likely work.
func NewServer(config *Config) (*Server, error) {
	if config.ListenHTTPS == "" && config.ListenHTTP == "" {
		return nil, errListenAddrMissing
	}
	if config.ListenHTTPS != "" {
		if config.KeyFile == "" {
			return nil, errKeyFileMissing
		}
		if config.CertFile == "" {
			return nil, errCertFileMissing
		}
	}
	clipboard, err := newClipboard(config)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:    config,
		clipboard: clipboard,
		visitors:  make(map[string]*visitor),
		routes:    nil,
	}, nil
}

func (s *Server) routeList() []route {
	s.Lock()
	defer s.Unlock()
	if s.routes != nil {
		return s.routes
	}

	s.routes = []route{
		newRoute("GET", "/", s.handleRoot),
		newRoute("PUT", "/(random)?", s.limit(s.auth(s.handleClipboardPutRandom))),
		newRoute("POST", "/(random)?", s.limit(s.auth(s.handleClipboardPutRandom))),
		newRoute("GET", "/static/.+", s.onlyIfWebUI(s.handleStatic)),
		newRoute("GET", "/info", s.limit(s.handleInfo)),
		newRoute("GET", "/verify", s.limit(s.auth(s.handleVerify))),
		newRoute("GET", "/(?i)([a-z0-9][-_.a-z0-9]{1,100})", s.limit(s.auth(s.handleClipboardGet))),
		newRoute("HEAD", "/(?i)([a-z0-9][-_.a-z0-9]{1,100})", s.limit(s.auth(s.handleClipboardHead))),
		newRoute("PUT", "/(?i)([a-z0-9][-_.a-z0-9]{1,100})", s.limit(s.auth(s.handleClipboardPut))),
		newRoute("POST", "/(?i)([a-z0-9][-_.a-z0-9]{1,100})", s.limit(s.auth(s.handleClipboardPut))),
	}
	return s.routes
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	for _, route := range s.routeList() {
		matches := route.regex.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 && r.Method == route.method {
			log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
			ctx := context.WithValue(r.Context(), routeCtx{}, matches[1:])
			if err := route.handler(w, r.WithContext(ctx)); err != nil {
				if err == errInvalidFileID {
					s.fail(w, r, http.StatusBadRequest, err)
				} else if e, ok := err.(*errHTTPNotOK); ok {
					s.fail(w, r, e.code, e)
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

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) error {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	salt := ""
	if s.config.Key != nil {
		salt = base64.StdEncoding.EncodeToString(s.config.Key.Salt)
	}

	response := &httpResponseServerInfo{
		ServerAddr: s.config.ServerAddr,
		Salt:       salt,
	}

	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) error {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	return nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("User-Agent"), "curl/") {
		return s.handleCurlRoot(w, r)
	}
	return s.onlyIfWebUI(s.redirectHTTPS(s.handleWebRoot))(w, r)
}

func (s *Server) handleWebRoot(w http.ResponseWriter, r *http.Request) error {
	return webTemplate.Execute(w, &webTemplateConfig{
		KeyDerivIter: keyDerivIter,
		KeyLenBytes:  keyLenBytes,
		DefaultPort:  DefaultPort,
		Config:       s.config,
	})
}

func (s *Server) handleCurlRoot(w http.ResponseWriter, r *http.Request) error {
	return curlTemplate.Execute(w, &webTemplateConfig{Config: s.config})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) error {
	r.URL.Path = "/web" + r.URL.Path // This is a hack to get the embedded path
	http.FileServer(http.FS(webStaticFs)).ServeHTTP(w, r)
	return nil
}

func (s *Server) handleClipboardGet(w http.ResponseWriter, r *http.Request) error {
	fields := r.Context().Value(routeCtx{}).([]string)
	id := fields[0]
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

	return s.clipboard.ReadFile(id, newSniffWriter(w))
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
	return s.writeFileInfoOutput(w, id, stat.Expires, ttl, formatHeadersOnly)
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

	// Read query params
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
	ttl, err := s.getTTL(r)
	if err != nil {
		return err
	}
	expires := int64(0)
	if ttl > 0 {
		expires = time.Now().Add(ttl).Unix()
	}

	// Always delete file first to avoid awkward FIFO/regular-file behavior
	s.clipboard.DeleteFile(id)

	// Ensure that we update the limiters and such!
	defer s.updateStatsAndExpire()

	// TODO this is bad when things crash
	// TODO i hate this reservation stuff
	if reserve {
		reservationExpires := time.Now().Add(reserveTTL).Unix()
		if err := s.clipboard.WriteMeta(id, FileModeReadWrite, reservationExpires); err != nil {
			return err
		}
	} else {
		if err := s.clipboard.WriteMeta(id, fileMode, expires); err != nil {
			return err
		}
	}

	// Handle empty body
	body := r.Body
	if body == nil {
		body = io.NopCloser(strings.NewReader(""))
	}

	// If this is a stream, make fifo device instead of file if type is set to "fifo".
	// Also, we want to immediately output instructions.
	if streamMode != streamModeNoStream {
		if err := s.clipboard.MakePipe(id); err != nil {
			return err
		}
		if streamMode == streamModeImmediateHeaders {
			// Oh wow here comes a hack: for very short POST payloads, "curl -d.." will (obviously) not send the
			// "Expect: 100-continue" header, so the body is immediately consumed and closed by Go's HTTP server,
			// yielding a http.ErrBodyReadAfterClose error. To counter this behavior in streaming mode, we consume
			// the entire request body if it is short enough (<50 KB). In practice, curl will send "Expect: 100-continue"
			// for anything > ~1400 bytes.
			// TODO test short POST payload with curl "curl -dabc nopaste.net?s=1"
			if r.Header.Get("Expect") == "" && r.ContentLength < 50*1024 {
				buf := make([]byte, r.ContentLength)
				_, err := io.ReadFull(body, buf)
				if err != nil {
					return err
				}
				body = io.NopCloser(bytes.NewReader(buf))
			}
			if err := s.writeFileInfoOutput(w, id, expires, ttl, format); err != nil {
				return err
			}
		}
	}

	// Copy file contents (with file limit & total limit)
	if err := s.clipboard.WriteFile(id, body); err != nil {
		if err == errLimitReached {
			return ErrHTTPPayloadTooLarge
		} else if err == errBrokenPipe {
			// This happens when interrupting on receiver-side while streaming. We treat this as a success.
			return ErrHTTPPartialContent
		}
		return err
	}

	// Output URL, TTL, etc.
	if streamMode == streamModeNoStream || streamMode == streamModeDelayHeaders {
		if err := s.writeFileInfoOutput(w, id, expires, ttl, format); err != nil {
			s.clipboard.DeleteFile(id)
			return err
		}
	}

	return nil
}

// checkPUT verifies that the PUT against the given ID is allowed. It also increases
// clipboard count limits and visitor limits.
func (s *Server) checkPUT(id string, remoteAddr string) error {
	stat, _ := s.clipboard.Stat(id)
	if stat == nil {
		// File does not exist

		// Check visitor file count limit
		v := s.getVisitor(remoteAddr)
		if err := v.countLimiter.Add(1); err != nil {
			return ErrHTTPTooManyRequests
		}

		// Check total file count limit
		if err := s.clipboard.Add(); err != nil {
			return ErrHTTPTooManyRequests
		}
	} else {
		// File exists

		// File not writable
		m, err := s.clipboard.Stat(id)
		if err != nil {
			return err
		}
		if m.Mode != FileModeReadWrite {
			return ErrHTTPMethodNotAllowed
		}
	}
	return nil
}

func (s *Server) writeFileInfoOutput(w http.ResponseWriter, id string, expires int64, ttl time.Duration, format string) error {
	url, err := s.config.GenerateClipURL(id, ttl) // TODO this is horrible
	if err != nil {
		return err
	}
	path := fmt.Sprintf(clipboardPathFormat, id)
	curl, err := s.config.GenerateCurlCommand(path, ttl)
	if err != nil {
		curl = ""
	}

	w.Header().Set(headerURL, url)
	w.Header().Set(headerFile, id)
	w.Header().Set(headerTTL, fmt.Sprintf("%d", int(ttl.Seconds())))
	w.Header().Set(headerExpires, fmt.Sprintf("%d", expires))
	w.Header().Set(headerCurl, curl)

	if format == formatJSON {
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
	} else if format == formatText {
		info := &FileInfo{
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
	if r.Header.Get(headerFileMode) != "" {
		mode = r.Header.Get(headerFileMode)
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

func (s *Server) getTTL(r *http.Request) (time.Duration, error) {
	var err error
	var ttl time.Duration
	if r.URL.Query().Get(queryParamTTL) != "" {
		ttl, err = parseDuration(r.URL.Query().Get(queryParamTTL))
	} else if r.Header.Get(headerTTL) != "" {
		ttl, err = parseDuration(r.Header.Get(headerTTL))
	} else if s.config.FileExpireAfter > 0 {
		ttl = s.config.FileExpireAfter
	}
	if err != nil {
		return 0, ErrHTTPBadRequest
	}
	if s.config.FileExpireAfter > 0 && ttl > s.config.FileExpireAfter {
		ttl = s.config.FileExpireAfter // TODO test TTL
	}
	return ttl, nil
}

func (s *Server) getStreamMode(r *http.Request) (string, error) {
	mode := streamModeNoStream
	if r.URL.Query().Get(queryParamStream) != "" {
		mode = r.URL.Query().Get(queryParamStream)
	} else if r.Header.Get(headerStream) != "" {
		mode = r.Header.Get(headerStream)
	}
	if mode != streamModeNoStream && mode != streamModeImmediateHeaders && mode != streamModeDelayHeaders {
		return "", errInvalidStreamMode
	}
	return mode, nil
}

func (s *Server) isReserve(r *http.Request) bool {
	return r.Header.Get(headerReserve) == "yes" || r.URL.Query().Get(queryParamStreamReserve) == "1"
}

func (s *Server) getOutputFormat(r *http.Request) string {
	if r.Header.Get(headerFormat) == formatJSON || r.URL.Query().Get(queryParamFormat) == formatJSON {
		return formatJSON
	} else if r.Header.Get(headerFormat) == formatHeadersOnly || r.URL.Query().Get(queryParamFormat) == formatHeadersOnly {
		return formatHeadersOnly
	}
	return formatText
}

func (s *Server) auth(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := s.authorize(r); err != nil {
			return err
		}
		return next(w, r)
	}
}

func (s *Server) authorize(r *http.Request) error {
	if s.config.Key == nil {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if encodedQueryAuth, ok := r.URL.Query()[queryParamAuth]; ok && len(encodedQueryAuth) > 0 {
		queryAuth, err := base64.RawURLEncoding.DecodeString(encodedQueryAuth[0])
		if err != nil {
			log.Printf("%s - %s %s - cannot decode query auth override", r.RemoteAddr, r.Method, r.RequestURI)
			return ErrHTTPUnauthorized
		}
		auth = string(queryAuth)
	}

	if m := authHmacRegex.FindStringSubmatch(auth); m != nil {
		return s.authorizeHmac(r, m)
	} else if m := authBasicRegex.FindStringSubmatch(auth); m != nil {
		return s.authorizeBasic(r, m)
	} else {
		log.Printf("%s - %s %s - auth header missing", r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}
}

func (s *Server) authorizeHmac(r *http.Request, matches []string) error {
	timestamp, err := strconv.Atoi(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - hmac timestamp conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	ttlSecs, err := strconv.Atoi(matches[2])
	if err != nil {
		log.Printf("%s - %s %s - hmac ttl conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	hash, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		log.Printf("%s - %s %s - hmac base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	// Recalculate HMAC
	// TODO this should include the query string
	data := []byte(fmt.Sprintf("%d:%d:%s:%s", timestamp, ttlSecs, r.Method, r.URL.Path))
	hm := hmac.New(sha256.New, s.config.Key.Bytes)
	if _, err := hm.Write(data); err != nil {
		log.Printf("%s - %s %s - hmac calculation: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}
	rehash := hm.Sum(nil)

	// Compare HMAC in constant time (to prevent timing attacks)
	if subtle.ConstantTimeCompare(hash, rehash) != 1 {
		log.Printf("%s - %s %s - hmac invalid", r.RemoteAddr, r.Method, r.RequestURI)
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
			log.Printf("%s - %s %s - hmac request age mismatch", r.RemoteAddr, r.Method, r.RequestURI)
			return ErrHTTPUnauthorized
		}
	}

	return nil
}

func (s *Server) authorizeBasic(r *http.Request, matches []string) error {
	userPassBytes, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - basic base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return ErrHTTPUnauthorized
	}

	userPassParts := strings.Split(string(userPassBytes), ":")
	if len(userPassParts) != 2 {
		log.Printf("%s - %s %s - basic invalid user/pass format", r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}
	passwordBytes := []byte(userPassParts[1])

	// Compare HMAC in constant time (to prevent timing attacks)
	key := DeriveKey(passwordBytes, s.config.Key.Salt)
	if subtle.ConstantTimeCompare(key.Bytes, s.config.Key.Bytes) != 1 {
		log.Printf("%s - %s %s - basic invalid", r.RemoteAddr, r.Method, r.RequestURI)
		return ErrHTTPUnauthorized
	}

	return nil
}

func (s *Server) serverManager() {
	ticker := time.NewTicker(managerTickerInterval)
	for {
		s.updateStatsAndExpire()
		<-ticker.C
	}
}

func (s *Server) updateStatsAndExpire() {
	s.Lock()
	defer s.Unlock()

	// Expire visitors from rate visitors map
	for ip, v := range s.visitors {
		if time.Since(v.lastSeen) > visitorExpungeAfter {
			delete(s.visitors, ip)
		}
	}

	// Walk clipboard to update size/count limiters, and expire/delete files
	if err := s.clipboard.Expire(); err != nil {
		log.Printf("cannot expire clipboard entries: %s", err.Error())
	}

	stats, err := s.clipboard.Stats()
	if err != nil {
		log.Printf("cannot get stats from clipboard: %s", err.Error())
	} else {
		s.printStats(stats)
	}
}

func (s *Server) printStats(stats *clipboardStats) {
	var countLimit, sizeLimit string
	if s.config.ClipboardCountLimit == 0 {
		countLimit = "no limit"
	} else {
		countLimit = fmt.Sprintf("max %d", s.config.ClipboardCountLimit)
	}
	if s.config.ClipboardSizeLimit == 0 {
		sizeLimit = "no limit"
	} else {
		sizeLimit = fmt.Sprintf("max %s", BytesToHuman(s.config.ClipboardSizeLimit))
	}
	log.Printf("files: %d (%s), size: %s (%s), visitors: %d (last 3 minutes)",
		stats.NumFiles, countLimit, BytesToHuman(stats.Size), sizeLimit, len(s.visitors))
}

func (s *Server) onlyIfWebUI(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		if !s.config.WebUI {
			return ErrHTTPBadRequest
		}

		return next(w, r)
	}
}

func (s *Server) redirectHTTPS(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.TLS == nil && s.config.ListenHTTPS != "" {
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
func (s *Server) limit(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		v := s.getVisitor(r.RemoteAddr)
		if !v.rateLimiter.Allow() {
			return ErrHTTPTooManyRequests
		}

		return next(w, r)
	}
}

// getVisitor creates or retrieves a rate.Limiter for the given visitor.
// This function was taken from https://www.alexedwards.net/blog/how-to-rate-limit-http-requests (MIT).
func (s *Server) getVisitor(remoteAddr string) *visitor {
	s.Lock()
	defer s.Unlock()

	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr // This should not happen in real life; only in tests.
	}

	v, exists := s.visitors[ip]
	if !exists {
		v = &visitor{
			newLimiter(int64(s.config.FileCountPerVisitorLimit)),
			rate.NewLimiter(visitorRequestsPerSecond, visitorRequestsPerSecondBurst),
			time.Now(),
		}
		s.visitors[ip] = v
		return v
	}

	v.lastSeen = time.Now()
	return v
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("%s - %s %s - %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
	w.WriteHeader(code)
	w.Write([]byte(http.StatusText(code)))
}

type errHTTPNotOK struct {
	code   int
	status string
}

func (e errHTTPNotOK) Error() string {
	return fmt.Sprintf("http: %s", e.status)
}

// ErrHTTPPartialContent is returned when the client interrupts a stream and only partial content was sent
var ErrHTTPPartialContent = &errHTTPNotOK{http.StatusPartialContent, http.StatusText(http.StatusPartialContent)}

// ErrHTTPBadRequest is returned when the request sent by the client was invalid, e.g. invalid file name
var ErrHTTPBadRequest = &errHTTPNotOK{http.StatusBadRequest, http.StatusText(http.StatusBadRequest)}

// ErrHTTPMethodNotAllowed is returned when the file state does not allow the current method, e.g. PUTting a read-only file
var ErrHTTPMethodNotAllowed = &errHTTPNotOK{http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed)}

// ErrHTTPNotFound is returned when a resource is not found on the server
var ErrHTTPNotFound = &errHTTPNotOK{http.StatusNotFound, http.StatusText(http.StatusNotFound)}

// ErrHTTPTooManyRequests is returned when a server-side rate limit has been reached
var ErrHTTPTooManyRequests = &errHTTPNotOK{http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests)}

// ErrHTTPPayloadTooLarge is returned when the clipboard/file-size limit has been reached
var ErrHTTPPayloadTooLarge = &errHTTPNotOK{http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge)}

// ErrHTTPUnauthorized is returned when the client has not sent proper credentials
var ErrHTTPUnauthorized = &errHTTPNotOK{http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)}

var errListenAddrMissing = errors.New("listen address missing, add 'ListenHTTPS' or 'ListenHTTP' to config or pass --listen-http(s)")
var errKeyFileMissing = errors.New("private key file missing, add 'KeyFile' to config or pass --keyfile")
var errCertFileMissing = errors.New("certificate file missing, add 'CertFile' to config or pass --certfile")
var errClipboardDirNotWritable = errors.New("clipboard dir not writable by user")
var errInvalidFileID = errors.New("invalid file id")
var errInvalidStreamMode = errors.New("invalid stream mode")
var errNoMatchingRoute = errors.New("no matching route")
