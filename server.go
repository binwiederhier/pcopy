package pcopy

import (
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
	visitorCountLimit             = 100
	visitorRequestsPerSecond      = 2
	visitorRequestsPerSecondBurst = 5
	visitorExpungeAfter           = 3 * time.Minute
	certCommonName                = "pcopy"

	headerStream            = "X-Stream"
	headerReserve           = "X-Reserve"
	headerFormat            = "X-Format"
	headerFileMode          = "X-Mode"
	headerFile              = "X-File"
	headerTTL               = "X-TTL"
	headerURL               = "X-Url"
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

// server is the main HTTP server struct. It's the one with all the good stuff.
type server struct {
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
	KeyDerivIter     int
	KeyLenBytes      int
	CurlPinnedPubKey string
	DefaultPort      int
	Config           *Config
}

// Serve starts a server and listens for incoming HTTPS requests. The server handles all management operations (info,
// verify, ...), as well as the actual clipboard functionality (GET/PUT/POST). It also starts a background process
// to prune old
func Serve(config *Config) error {
	server, err := newServer(config)
	if err != nil {
		return err
	}
	go server.serverManager()
	return server.listenAndServe()
}

func newServer(config *Config) (*server, error) {
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
	return &server{
		config:    config,
		clipboard: clipboard,
		visitors:  make(map[string]*visitor),
		routes:    nil,
	}, nil
}

func (s *server) listenAndServe() error {
	listens := make([]string, 0)
	if s.config.ListenHTTP != "" {
		listens = append(listens, fmt.Sprintf("%s/http", s.config.ListenHTTP))
	}
	if s.config.ListenHTTPS != "" {
		listens = append(listens, fmt.Sprintf("%s/https", s.config.ListenHTTPS))
	}
	if s.config.Key == nil {
		log.Printf("Listening on %s (UNPROTECTED CLIPBOARD)\n", strings.Join(listens, " "))
	} else {
		log.Printf("Listening on %s\n", strings.Join(listens, " "))
	}

	http.HandleFunc("/", s.handle)

	errChan := make(chan error)
	if s.config.ListenHTTP != "" {
		go func() {
			if err := http.ListenAndServe(s.config.ListenHTTP, nil); err != nil {
				errChan <- err
			}
		}()
	}
	if s.config.ListenHTTPS != "" {
		go func() {
			if err := http.ListenAndServeTLS(s.config.ListenHTTPS, s.config.CertFile, s.config.KeyFile, nil); err != nil {
				errChan <- err
			}
		}()
	}
	err := <-errChan
	return err
}

func (s *server) routeList() []route {
	s.Lock()
	defer s.Unlock()
	if s.routes != nil {
		return s.routes
	}

	s.routes = []route{
		newRoute("GET", "/", s.handleRoot),
		newRoute("PUT", "/", s.limit(s.auth(s.handleClipboardPutRandom))),
		newRoute("POST", "/", s.limit(s.auth(s.handleClipboardPutRandom))),
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

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
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

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) error {
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

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) error {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	return nil
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("User-Agent"), "curl/") {
		return s.handleCurlRoot(w, r)
	}
	return s.onlyIfWebUI(s.redirectHTTPS(s.handleWebRoot))(w, r)
}

func (s *server) handleWebRoot(w http.ResponseWriter, r *http.Request) error {
	var err error
	curlPinnedPubKey := ""
	if r.TLS != nil {
		curlPinnedPubKey, err = ReadCurlPinnedPublicKeyFromFile(s.config.CertFile)
		if err != nil {
			return err
		}
	}
	return webTemplate.Execute(w, &webTemplateConfig{
		KeyDerivIter:     keyDerivIter,
		KeyLenBytes:      keyLenBytes,
		CurlPinnedPubKey: curlPinnedPubKey,
		DefaultPort:      DefaultPort,
		Config:           s.config,
	})
}

func (s *server) handleCurlRoot(w http.ResponseWriter, r *http.Request) error {
	return curlTemplate.Execute(w, &webTemplateConfig{Config: s.config})
}

func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) error {
	r.URL.Path = "/web" + r.URL.Path // This is a hack to get the embedded path
	http.FileServer(http.FS(webStaticFs)).ServeHTTP(w, r)
	return nil
}

func (s *server) handleClipboardGet(w http.ResponseWriter, r *http.Request) error {
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

	s.clipboard.ReadFile(id, w)

	return nil
}

func (s *server) handleClipboardHead(w http.ResponseWriter, r *http.Request) error {
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

func (s *server) handleClipboardPutRandom(w http.ResponseWriter, r *http.Request) error {
	ctx := context.WithValue(r.Context(), routeCtx{}, []string{randomFileID()})
	return s.handleClipboardPut(w, r.WithContext(ctx))
}

func (s *server) handleClipboardPut(w http.ResponseWriter, r *http.Request) error {
	// Parse request: file ID, stream
	fields := r.Context().Value(routeCtx{}).([]string)
	id := fields[0]

	// Handle empty body
	if r.Body == nil {
		r.Body = io.NopCloser(strings.NewReader(""))
	}

	// Check if file exists
	reserved := false
	stat, _ := s.clipboard.Stat(id)
	if stat == nil {
		// File does not exist

		// Check visitor file count limit
		v := s.getVisitor(r)
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
		reserved = m.Reserved
	}

	// Read query params
	format := s.outputFormat(r)
	stream := s.isStream(r)
	reserve := s.isReserve(r)
	earlyResponse := stream && !reserved
	mode, err := s.getFileMode(r)
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
	if reserve {
		mode = FileModeReadWrite
		expires = time.Now().Add(10 * time.Second).Unix()
	}

	// Always delete file first to avoid awkward FIFO/regular-file behavior
	s.clipboard.DeleteFile(id)

	// Ensure that we update the limiters and such!
	defer s.updateStatsAndExpire()

	// TODO this is bad when things crash
	if err := s.clipboard.WriteMeta(id, mode, expires, reserve); err != nil {
		return err
	}

	// If this is a stream, make fifo device instead of file if type is set to "fifo".
	// Also, we want to immediately output instructions.
	if stream {
		if err := s.clipboard.MakePipe(id); err != nil {
			return err
		}
		if earlyResponse {
			if err := s.writeFileInfoOutput(w, id, expires, ttl, format); err != nil {
				return err
			}
		}
	}

	// Copy file contents (with file limit & total limit)
	if err := s.clipboard.WriteFile(id, r.Body); err != nil {
		if err == errLimitReached {
			return ErrHTTPPayloadTooLarge
		} else if err == errBrokenPipe {
			// This happens when interrupting on receiver-side while streaming. We treat this as a success.
			return ErrHTTPPartialContent
		}
		return err
	}

	// Output URL, TTL, etc.
	if !earlyResponse {
		if err := s.writeFileInfoOutput(w, id, expires, ttl, format); err != nil {
			s.clipboard.DeleteFile(id)
			return err
		}
	}

	return nil
}

func (s *server) writeFileInfoOutput(w http.ResponseWriter, id string, expires int64, ttl time.Duration, format string) error {
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

func (s *server) getFileMode(r *http.Request) (string, error) {
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

func (s *server) getTTL(r *http.Request) (time.Duration, error) {
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

func (s *server) isStream(r *http.Request) bool {
	return r.Header.Get(headerStream) == "yes" || r.URL.Query().Get(queryParamStream) == "1"
}

func (s *server) isReserve(r *http.Request) bool {
	return r.Header.Get(headerReserve) == "yes" || r.URL.Query().Get(queryParamStreamReserve) == "1"
}

func (s *server) outputFormat(r *http.Request) string {
	if r.Header.Get(headerFormat) == "json" || r.URL.Query().Get(queryParamFormat) == "json" {
		return "json"
	}
	return "text"
}

func (s *server) auth(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := s.authorize(r); err != nil {
			return err
		}
		return next(w, r)
	}
}

func (s *server) authorize(r *http.Request) error {
	if s.config.Key == nil {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if encodedQueryAuth, ok := r.URL.Query()[queryParamAuth]; ok && len(encodedQueryAuth) > 0 {
		queryAuth, err := base64.StdEncoding.DecodeString(encodedQueryAuth[0])
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

func (s *server) authorizeHmac(r *http.Request, matches []string) error {
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

func (s *server) authorizeBasic(r *http.Request, matches []string) error {
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

func (s *server) serverManager() {
	ticker := time.NewTicker(managerTickerInterval)
	for {
		s.updateStatsAndExpire()
		<-ticker.C
	}
}

func (s *server) updateStatsAndExpire() {
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

func (s *server) printStats(stats *clipboardStats) {
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

func (s *server) onlyIfWebUI(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		if !s.config.WebUI {
			return ErrHTTPBadRequest
		}

		return next(w, r)
	}
}

func (s *server) redirectHTTPS(next handlerFnWithErr) handlerFnWithErr {
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
func (s *server) limit(next handlerFnWithErr) handlerFnWithErr {
	return func(w http.ResponseWriter, r *http.Request) error {
		v := s.getVisitor(r)
		if !v.rateLimiter.Allow() {
			return ErrHTTPTooManyRequests
		}

		return next(w, r)
	}
}

// getVisitor creates or retrieves a rate.Limiter for the given visitor.
// This function was taken from https://www.alexedwards.net/blog/how-to-rate-limit-http-requests (MIT).
func (s *server) getVisitor(r *http.Request) *visitor {
	s.Lock()
	defer s.Unlock()

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // This should not happen in real life; only in tests.
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

func (s *server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
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
var errNoMatchingRoute = errors.New("no matching route")
