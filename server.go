package pcopy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

const (
	managerTickerInterval      = 30 * time.Second
	defaultMaxAuthAge          = time.Minute
	noAuthRequestAge           = 0
	rateLimitRequestsPerSecond = 2
	rateLimitBurstPerSecond    = 5
	rateLimitExpungeAfter      = 3 * time.Minute
	certCommonName             = "pcopy"
)

const (
	pathRoot     = "/"
	pathInfo     = "/info"
	pathVerify   = "/verify"
	pathInstall  = "/install"
	pathDownload = "/download"
	pathJoin     = "/join"
	pathStatic   = "/static"
)

var (
	authOverrideParam   = "a"
	authHmacFormat      = "HMAC %d %d %s" // timestamp ttl b64-hmac
	authHmacRegex       = regexp.MustCompile(`^HMAC (\d+) (\d+) (.+)$`)
	authBasicRegex      = regexp.MustCompile(`^Basic (\S+)$`)
	clipboardRegex      = regexp.MustCompile(`^/([-_a-zA-Z0-9]{1,100})$`)
	clipboardPathFormat = "/%s"
	reservedPaths       = []string{pathRoot, pathInfo, pathVerify, pathInstall, pathDownload, pathJoin, pathStatic}

	//go:embed "web/index.gohtml"
	webTemplateSource string
	webTemplate       = template.Must(template.New("index").Funcs(templateFnMap).Parse(webTemplateSource))

	//go:embed web/static
	webStaticFs embed.FS

	//go:embed "scripts/join.sh.tmpl"
	joinTemplateSource string
	joinTemplate       = template.Must(template.New("join").Funcs(templateFnMap).Parse(joinTemplateSource))

	//go:embed "scripts/install.sh.tmpl"
	installTemplateSource string
	installTemplate       = template.Must(template.New("install").Funcs(templateFnMap).Parse(installTemplateSource))
)

// infoResponse is the response returned by the / endpoint
type infoResponse struct {
	ServerAddr string `json:"serverAddr"`
	Salt       string `json:"salt"`
}

type server struct {
	config       *Config
	countLimiter *limiter
	sizeLimiter  *limiter
	rateLimiter  map[string]*visitor
	sync.Mutex
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
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
	return server.listenAndServeTLS()
}

func newServer(config *Config) (*server, error) {
	if config.ListenAddr == "" {
		return nil, errListenAddrMissing
	}
	if config.KeyFile == "" {
		return nil, errKeyFileMissing
	}
	if config.CertFile == "" {
		return nil, errCertFileMissing
	}
	if err := os.MkdirAll(config.ClipboardDir, 0700); err != nil {
		return nil, errClipboardDirNotWritable
	}
	if unix.Access(config.ClipboardDir, unix.W_OK) != nil {
		return nil, errClipboardDirNotWritable
	}
	return &server{
		config:       config,
		sizeLimiter:  newLimiter(config.ClipboardSizeLimit),
		countLimiter: newLimiter(int64(config.ClipboardCountLimit)),
		rateLimiter:  make(map[string]*visitor),
	}, nil
}

func (s *server) listenAndServeTLS() error {
	if s.config.Key == nil {
		log.Printf("Listening on %s (UNPROTECTED CLIPBOARD)\n", s.config.ListenAddr)
	} else {
		log.Printf("Listening on %s\n", s.config.ListenAddr)
	}

	http.HandleFunc(pathInfo, s.limit(s.handleInfo))
	http.HandleFunc(pathVerify, s.limit(s.handleVerify))
	http.HandleFunc(pathInstall, s.limit(s.handleInstall))
	http.HandleFunc(pathJoin, s.limit(s.handleJoin))
	http.HandleFunc(pathDownload, s.limit(s.handleDownload))
	http.HandleFunc(pathRoot, s.handleDefault) // Rate limiting for clipboard in handleClipboard

	return http.ListenAndServeTLS(s.config.ListenAddr, s.config.CertFile, s.config.KeyFile, nil)
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	salt := ""
	if s.config.Key != nil {
		salt = base64.StdEncoding.EncodeToString(s.config.Key.Salt)
	}

	response := &infoResponse{
		ServerAddr: s.config.ServerAddr,
		Salt:       salt,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
}

func (s *server) handleDefault(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == pathRoot {
		if !s.config.WebUI || r.Method != http.MethodGet {
			s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
			return
		}
		s.handleWebRoot(w, r)
	} else if strings.HasPrefix(r.URL.Path, pathStatic+string(os.PathSeparator)) {
		if !s.config.WebUI || r.Method != http.MethodGet {
			s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
			return
		}
		s.handleWebStatic(w, r)
	} else {
		s.limit(s.handleClipboard)(w, r)
	}
}
func (s *server) handleWebRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	if err := webTemplate.Execute(w, s.config); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
	}
}

func (s *server) handleWebStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	r.URL.Path = "/web" + r.URL.Path // This is a hack to get the embedded path
	http.FileServer(http.FS(webStaticFs)).ServeHTTP(w, r)
}

func (s *server) handleClipboard(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	file, err := s.getClipboardFile(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	if r.Method == http.MethodGet {
		s.handleClipboardGet(w, r, file)
	} else if r.Method == http.MethodPut || r.Method == http.MethodPost {
		s.handleClipboardPut(w, r, file)
	}
}

func (s *server) handleClipboardGet(w http.ResponseWriter, r *http.Request, file string) {
	stat, err := os.Stat(file)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Length", strconv.FormatInt(stat.Size(), 10))
	f, err := os.Open(file)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, err)
		return
	}
	defer f.Close()

	if _, err = io.Copy(w, f); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleClipboardPut(w http.ResponseWriter, r *http.Request, file string) {
	// Check total file count limit (only if file didn't exist already)
	stat, _ := os.Stat(file)
	if stat == nil {
		if err := s.countLimiter.Add(1); err != nil {
			s.fail(w, r, http.StatusBadRequest, err)
			return
		}
	}

	// Create new file or truncate existing
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		s.countLimiter.Sub(1)
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	defer f.Close()
	defer s.updateStatsAndExpire()

	// Handle empty body
	if r.Body == nil {
		return
	}

	// Copy file contents (with file limit & total limit)
	fileSizeLimiter := newLimiter(s.config.FileSizeLimit)
	limitWriter := newLimitWriter(f, fileSizeLimiter, s.sizeLimiter)

	if _, err := io.Copy(limitWriter, r.Body); err != nil {
		if err == errLimitReached {
			s.fail(w, r, http.StatusBadRequest, err)
		} else {
			s.fail(w, r, http.StatusInternalServerError, err)
		}
		os.Remove(file)
		return
	}
	if r.Body.Close() != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		os.Remove(file)
		return
	}
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	executable, err := getExecutable()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}

	f, err := os.Open(executable)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	if _, err = io.Copy(w, f); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleInstall(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	if err := installTemplate.Execute(w, s.config); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusBadRequest, errInvalidMethod)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if err := joinTemplate.Execute(w, s.config); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) getClipboardFile(r *http.Request) (string, error) {
	for _, path := range reservedPaths {
		if r.URL.Path == path {
			return "", errInvalidFileID
		}
	}
	matches := clipboardRegex.FindStringSubmatch(r.URL.Path)
	if matches == nil {
		return "", errInvalidFileID
	}
	return fmt.Sprintf("%s/%s", s.config.ClipboardDir, matches[1]), nil
}

func (s *server) authorize(r *http.Request) error {
	if s.config.Key == nil {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if encodedQueryAuth, ok := r.URL.Query()[authOverrideParam]; ok && len(encodedQueryAuth) > 0 {
		queryAuth, err := base64.StdEncoding.DecodeString(encodedQueryAuth[0])
		if err != nil {
			log.Printf("%s - %s %s - cannot decode query auth override", r.RemoteAddr, r.Method, r.RequestURI)
			return errInvalidAuth
		}
		auth = string(queryAuth)
	}

	if m := authHmacRegex.FindStringSubmatch(auth); m != nil {
		return s.authorizeHmac(r, m)
	} else if m := authBasicRegex.FindStringSubmatch(auth); m != nil {
		return s.authorizeBasic(r, m)
	} else {
		log.Printf("%s - %s %s - auth header missing", r.RemoteAddr, r.Method, r.RequestURI)
		return errInvalidAuth
	}
}

func (s *server) authorizeHmac(r *http.Request, matches []string) error {
	timestamp, err := strconv.Atoi(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - hmac timestamp conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return errInvalidAuth
	}

	ttlSecs, err := strconv.Atoi(matches[2])
	if err != nil {
		log.Printf("%s - %s %s - hmac ttl conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return errInvalidAuth
	}

	hash, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		log.Printf("%s - %s %s - hmac base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return errInvalidAuth
	}

	// Recalculate HMAC
	data := []byte(fmt.Sprintf("%d:%d:%s:%s", timestamp, ttlSecs, r.Method, r.URL.Path))
	hm := hmac.New(sha256.New, s.config.Key.Bytes)
	if _, err := hm.Write(data); err != nil {
		log.Printf("%s - %s %s - hmac calculation: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return errInvalidAuth
	}
	rehash := hm.Sum(nil)

	// Compare HMAC in constant time (to prevent timing attacks)
	if subtle.ConstantTimeCompare(hash, rehash) != 1 {
		log.Printf("%s - %s %s - hmac invalid", r.RemoteAddr, r.Method, r.RequestURI)
		return errInvalidAuth
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
			return errInvalidAuth
		}
	}

	return nil
}

func (s *server) authorizeBasic(r *http.Request, matches []string) error {
	userPassBytes, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - basic base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return errInvalidAuth
	}

	userPassParts := strings.Split(string(userPassBytes), ":")
	if len(userPassParts) != 2 {
		log.Printf("%s - %s %s - basic invalid user/pass format", r.RemoteAddr, r.Method, r.RequestURI)
		return errInvalidAuth
	}
	passwordBytes := []byte(userPassParts[1])

	// Compare HMAC in constant time (to prevent timing attacks)
	key := DeriveKey(passwordBytes, s.config.Key.Salt)
	if subtle.ConstantTimeCompare(key.Bytes, s.config.Key.Bytes) != 1 {
		log.Printf("%s - %s %s - basic invalid", r.RemoteAddr, r.Method, r.RequestURI)
		return errInvalidAuth
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

	// Expire visitors from rate limiter map
	for ip, v := range s.rateLimiter {
		if time.Since(v.lastSeen) > rateLimitExpungeAfter {
			delete(s.rateLimiter, ip)
		}
	}

	// Walk clipboard to update size/count limiters, and expire/delete files
	files, err := ioutil.ReadDir(s.config.ClipboardDir)
	if err != nil {
		log.Printf("error reading clipboard: %s", err.Error())
		return
	}
	numFiles := int64(0)
	totalSize := int64(0)
	for _, f := range files {
		if !s.maybeExpire(f) {
			numFiles++
			totalSize += f.Size()
		}
	}
	s.countLimiter.Set(numFiles)
	s.sizeLimiter.Set(totalSize)
	s.printStats()
}

func (s *server) printStats() {
	var countLimit, sizeLimit string
	if s.countLimiter.Limit() == 0 {
		countLimit = "no limit"
	} else {
		countLimit = fmt.Sprintf("max %d", s.countLimiter.Limit())
	}
	if s.sizeLimiter.Limit() == 0 {
		sizeLimit = "no limit"
	} else {
		sizeLimit = fmt.Sprintf("max %s", BytesToHuman(s.sizeLimiter.Limit()))
	}
	log.Printf("files: %d (%s), size: %s (%s), visitors: %d (last 3 minutes)",
		s.countLimiter.Value(), countLimit, BytesToHuman(s.sizeLimiter.Value()), sizeLimit, len(s.rateLimiter))
}

// maybeExpire deletes a file if it has expired and returns true if it did
func (s *server) maybeExpire(file os.FileInfo) bool {
	if s.config.FileExpireAfter == 0 || time.Since(file.ModTime()) <= s.config.FileExpireAfter {
		return false
	}
	if err := os.Remove(filepath.Join(s.config.ClipboardDir, file.Name())); err != nil {
		log.Printf("failed to remove clipboard entry after expiry: %s", err.Error())
	}
	log.Printf("removed expired entry: %s (%s)", file.Name(), BytesToHuman(file.Size()))
	return true
}

// limit wraps all HTTP endpoints and limits API use to a certain number of requests per second.
// This function was taken from https://www.alexedwards.net/blog/how-to-rate-limit-http-requests (MIT).
func (s *server) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, err)
			return
		}

		limiter := s.getVisitorLimiter(ip)
		if !limiter.Allow() {
			s.fail(w, r, http.StatusTooManyRequests, errRateLimitReached)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// getVisitorLimiter creates or retrieves a rate.Limiter for the given visitor.
// This function was taken from https://www.alexedwards.net/blog/how-to-rate-limit-http-requests (MIT).
func (s *server) getVisitorLimiter(ip string) *rate.Limiter {
	s.Lock()
	defer s.Unlock()

	v, exists := s.rateLimiter[ip]
	if !exists {
		limiter := rate.NewLimiter(rateLimitRequestsPerSecond, rateLimitBurstPerSecond)
		s.rateLimiter[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("%s - %s %s - %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
	w.WriteHeader(code)
	w.Write([]byte(http.StatusText(code)))
}

func getExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	realpath, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}

	return realpath, nil
}

var errListenAddrMissing = errors.New("listen address missing, add 'ListenAddr' to config or pass -listen")
var errKeyFileMissing = errors.New("private key file missing, add 'KeyFile' to config or pass -keyfile")
var errCertFileMissing = errors.New("certificate file missing, add 'CertFile' to config or pass -certfile")
var errClipboardDirNotWritable = errors.New("clipboard dir not writable by user")
var errInvalidAuth = errors.New("invalid auth")
var errInvalidMethod = errors.New("invalid method")
var errInvalidFileID = errors.New("invalid file id")
var errRateLimitReached = errors.New("rate limit reached")
