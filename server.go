package pcopy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	purgerTicketInterval = time.Second * 10
	defaultMaxAuthAge    = time.Minute
	noAuthRequestAge     = 0
)

var (
	hmacAuthFormat        = "HMAC %d %d %s" // timestamp ttl b64-hmac
	hmacAuthRegex         = regexp.MustCompile(`^HMAC (\d+) (\d+) (.+)$`)
	hmacAuthOverrideParam = "a"
	clipboardRegex        = regexp.MustCompile(`^/c(?:/([-_a-zA-Z0-9]*))$`)
	clipboardPathFormat   = "/c/%s"
	clipboardDefaultPath  = "/c"
)

type server struct {
	config *Config
}

func Serve(config *Config) error {
	server := &server{config: config}
	if err := server.checkConfig(); err != nil {
		return err
	}
	if config.ExpireAfter > 0 {
		go server.clipboardPurger()
	}
	return server.listenAndServeTLS()
}

func (s *server) checkConfig() error {
	if s.config.ListenAddr == "" {
		return listenAddrMissingError
	}
	if s.config.KeyFile == "" {
		return keyFileMissingError
	}
	if s.config.CertFile == "" {
		return certFileMissingError
	}
	if unix.Access(s.config.ClipboardDir, unix.W_OK) != nil {
		return clipboardDirNotWritableError
	}
	return nil
}

func (s *server) listenAndServeTLS() error {
	http.HandleFunc("/info", s.handleInfo)
	http.HandleFunc("/verify", s.handleVerify)
	http.HandleFunc("/install", s.handleInstall)
	http.HandleFunc("/join", s.handleJoin)
	http.HandleFunc("/download", s.handleDownload)
	http.HandleFunc("/c/", s.handleClipboard)
	http.HandleFunc("/c", s.handleClipboard)
	http.HandleFunc("/", s.handleWebUi)

	return http.ListenAndServeTLS(s.config.ListenAddr, s.config.CertFile, s.config.KeyFile, nil)
}

func (s *server) clipboardPurger() {
	ticker := time.NewTicker(purgerTicketInterval)
	for {
		<-ticker.C
		files, err := ioutil.ReadDir(s.config.ClipboardDir)
		if err != nil {
			log.Printf("failed to read clipboard dir: %s", err.Error())
			continue
		}
		for _, f := range files {
			if time.Now().Sub(f.ModTime()) > s.config.ExpireAfter {
				if err := os.Remove(filepath.Join(s.config.ClipboardDir, f.Name())); err != nil {
					log.Printf("failed to remove clipboard entry after expiry: %s", err.Error())
				}
				log.Printf("removed expired entry %s", f.Name())
			}
		}
	}
}

func (s *server) handleInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

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

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)
}

func (s *server) handleWebUi(w http.ResponseWriter, r *http.Request) {
	webUi := strings.ReplaceAll(webUiTemplate, "${serverAddr}", r.Host)
	w.Write([]byte(webUi))
}

func (s *server) handleClipboard(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	if err := os.MkdirAll(s.config.ClipboardDir, 0700); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}

	var id string
	matches := clipboardRegex.FindStringSubmatch(r.URL.Path)
	if matches == nil {
		id = DefaultId
	} else {
		id = matches[1]
	}
	file := fmt.Sprintf("%s/%s", s.config.ClipboardDir, id)

	if r.Method == http.MethodGet {
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
	} else if r.Method == http.MethodPut {
		f, err := os.Create(file)
		if err != nil {
			s.fail(w, r, http.StatusInternalServerError, err)
			return
		}
		defer f.Close()

		if r.Body != nil {
			if _, err = io.Copy(f, r.Body); err != nil {
				s.fail(w, r, http.StatusInternalServerError, err)
				return
			}
			if r.Body.Close() != nil {
				s.fail(w, r, http.StatusInternalServerError, err)
				return
			}
		}
	}
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

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

	var script string
	if s.config.ServerAddr != "" {
		script = s.installScript()
	} else {
		script = s.notConfiguredScript()
	}

	if _, err := w.Write([]byte(script)); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		s.fail(w, r, http.StatusUnauthorized, err)
		return
	}

	log.Printf("%s - %s %s", r.RemoteAddr, r.Method, r.RequestURI)

	var script string
	if s.config.ServerAddr != "" {
		script = s.joinScript()
	} else {
		script = s.notConfiguredScript()
	}

	if _, err := w.Write([]byte(script)); err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
}

func (s *server) authorize(r *http.Request) error {
	if s.config.Key == nil {
		return nil
	}

	auth := r.Header.Get("Authorization")
	if encodedQueryAuth, ok := r.URL.Query()[hmacAuthOverrideParam]; ok && len(encodedQueryAuth) > 0 {
		queryAuth, err := base64.StdEncoding.DecodeString(encodedQueryAuth[0])
		if err != nil {
			log.Printf("%s - %s %s - cannot decode query auth override", r.RemoteAddr, r.Method, r.RequestURI)
			return invalidAuthError
		}
		auth = string(queryAuth)
	}

	matches := hmacAuthRegex.FindStringSubmatch(auth)
	if matches == nil {
		log.Printf("%s - %s %s - auth header missing", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	timestamp, err := strconv.Atoi(matches[1])
	if err != nil {
		log.Printf("%s - %s %s - hmac timestamp conversion: %w", r.RemoteAddr, r.Method, r.RequestURI, err)
		return invalidAuthError
	}

	ttlSecs, err := strconv.Atoi(matches[2])
	if err != nil {
		log.Printf("%s - %s %s - hmac ttl conversion: %w", r.RemoteAddr, r.Method, r.RequestURI, err)
		return invalidAuthError
	}

	hash, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		log.Printf("%s - %s %s - hmac base64 conversion: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return invalidAuthError
	}

	// Recalculate HMAC
	data := []byte(fmt.Sprintf("%d:%d:%s:%s", timestamp, ttlSecs, r.Method, r.URL.Path))
	hm := hmac.New(sha256.New, s.config.Key.Bytes)
	if _, err := hm.Write(data); err != nil {
		log.Printf("%s - %s %s - hmac calculation: %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
		return invalidAuthError
	}
	rehash := hm.Sum(nil)

	// Compare HMAC in constant time (to prevent timing attacks)
	if subtle.ConstantTimeCompare(hash, rehash) != 1 {
		log.Printf("%s - %s %s - hmac invalid", r.RemoteAddr, r.Method, r.RequestURI)
		return invalidAuthError
	}

	// Compare timestamp (to prevent replay attacks)
	maxAge := defaultMaxAuthAge
	if ttlSecs > 0 {
		maxAge = time.Second * time.Duration(ttlSecs)
	}
	if maxAge > 0 {
		age := time.Now().Sub(time.Unix(int64(timestamp), 0))
		if age > maxAge {
			log.Printf("%s - %s %s - hmac request age mismatch", r.RemoteAddr, r.Method, r.RequestURI)
			return invalidAuthError
		}
	}

	return nil
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Printf("%s - %s %s - %s", r.RemoteAddr, r.Method, r.RequestURI, err.Error())
	w.WriteHeader(code)
	w.Write([]byte(fmt.Sprintf("%d", code)))
}

func(s *server) notConfiguredScript() string {
	return strings.Join([]string{scriptHeader, notConfiguredCommands}, "\n")
}

func (s *server) installScript() string {
	template := strings.Join([]string{scriptHeader, installCommands, joinInstructionsCommands}, "\n")
	return s.replaceScriptVars(template)
}

func (s *server) joinScript() string {
	template := strings.Join([]string{scriptHeader, joinCommands}, "\n")
	return s.replaceScriptVars(template)
}

func (s *server) replaceScriptVars(template string) string {
	template = strings.ReplaceAll(template, "${serverAddr}", ExpandServerAddr(s.config.ServerAddr))
	template = strings.ReplaceAll(template, "${key}", EncodeKey(s.config.Key))
	return template
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

// infoResponse is the response returned by the / endpoint
type infoResponse struct {
	ServerAddr string `json:"serverAddr"`
	Salt       string `json:"salt"`
}

const certCommonName = "pcopy"

var listenAddrMissingError = errors.New("listen address missing, add 'ListenAddr' to config or pass -listen")
var keyFileMissingError = errors.New("private key file missing, add 'KeyFile' to config or pass -keyfile")
var certFileMissingError = errors.New("certificate file missing, add 'CertFile' to config or pass -certfile")
var clipboardDirNotWritableError = errors.New("clipboard dir not writable by user")
var invalidAuthError = errors.New("invalid auth")

const scriptHeader = `#!/bin/sh
set -eu
`
const notConfiguredCommands = `echo 'Server not configured to allow simple install.'
echo 'If you are the administrator, set ServerAddr in config.'
`
const installCommands = `if [ ! -f /usr/bin/pcopy ]; then
  [ $(id -u) -eq 0 ] || { echo 'Must be root to install'; exit 1; }
  curl -sk https://${serverAddr}/download > /usr/bin/pcopy
  chmod +x /usr/bin/pcopy
  [ -f /usr/bin/pcp ] || ln -s /usr/bin/pcopy /usr/bin/pcp
  [ -f /usr/bin/ppaste ] || ln -s /usr/bin/pcopy /usr/bin/ppaste
  echo "Successfully installed /usr/bin/pcopy."
fi
`
const joinInstructionsCommands = `echo "To join this clipboard, run 'pcopy join ${serverAddr}', or type 'pcopy -help' for more help'."
`
const joinCommands = `PCOPY_KEY=${key} /usr/bin/pcopy join -auto ${serverAddr}
`

const webUiTemplate = `
<html>
<head>
  <title>pcopy</title>
	<style>
		body {
		  font-family: sans-serif;
		}
		a {
		  color: #369;
		}
		.note {
		  width: 500px;
		  margin: 50px auto;
		  font-size: 1.1em;
		  color: #333;
		  text-align: justify;
		}
		#drop-area {
		  border: 2px dashed #ccc;
		  border-radius: 20px;
		  width: 480px;
		  margin: 50px auto;
		  padding: 20px;
		}
		#drop-area.highlight {
		  border-color: purple;
		}
		p {
		  margin-top: 0;
		}
		.my-form {
		  margin-bottom: 10px;
		}
		#gallery {
		  margin-top: 10px;
		}
		#gallery img {
		  width: 150px;
		  margin-bottom: 10px;
		  margin-right: 10px;
		  vertical-align: middle;
		}
		.button {
		  display: inline-block;
		  padding: 10px;
		  background: #ccc;
		  cursor: pointer;
		  border-radius: 5px;
		  border: 1px solid #ccc;
		}
		.button:hover {
		  background: #ddd;
		}
		#fileElem {
		  display: none;
		}
	</style>
</head>
<body>
<div id="drop-area">
  <form class="my-form">
    <p>Upload multiple files with the file dialog or by dragging and dropping images onto the dashed region</p>
    <input type="file" id="fileElem" multiple accept="image/*" onchange="handleFiles(this.files)">
    <label class="button" for="fileElem">Select some files</label>
  </form>
  <progress id="progress-bar" max=100 value=0></progress>
  <div id="gallery" /></div>
</div>
<script>
// ************************ Drag and drop ***************** //
let dropArea = document.getElementById("drop-area")

// Prevent default drag behaviors
;['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
  dropArea.addEventListener(eventName, preventDefaults, false)   
  document.body.addEventListener(eventName, preventDefaults, false)
})

// Highlight drop area when item is dragged over it
;['dragenter', 'dragover'].forEach(eventName => {
  dropArea.addEventListener(eventName, highlight, false)
})

;['dragleave', 'drop'].forEach(eventName => {
  dropArea.addEventListener(eventName, unhighlight, false)
})

// Handle dropped files
dropArea.addEventListener('drop', handleDrop, false)

function preventDefaults (e) {
  e.preventDefault()
  e.stopPropagation()
}

function highlight(e) {
  dropArea.classList.add('highlight')
}

function unhighlight(e) {
  dropArea.classList.remove('active')
}

function handleDrop(e) {
  var dt = e.dataTransfer
  var files = dt.files

  handleFiles(files)
}

let uploadProgress = []
let progressBar = document.getElementById('progress-bar')

function initializeProgress(numFiles) {
  progressBar.value = 0
  uploadProgress = []

  for(let i = numFiles; i > 0; i--) {
    uploadProgress.push(0)
  }
}

function updateProgress(fileNumber, percent) {
  uploadProgress[fileNumber] = percent
  let total = uploadProgress.reduce((tot, curr) => tot + curr, 0) / uploadProgress.length
  console.debug('update', fileNumber, percent, total)
  progressBar.value = total
}

function handleFiles(files) {
  files = [...files]
  initializeProgress(files.length)
  files.forEach(uploadFile)
  files.forEach(previewFile)
}

function previewFile(file) {
  let reader = new FileReader()
  reader.readAsDataURL(file)
  reader.onloadend = function() {
    let img = document.createElement('img')
    img.src = reader.result
    document.getElementById('gallery').appendChild(img)
  }
}

function uploadFile(file, i) {
  var url = 'https://${serverAddr}/c'
  var xhr = new XMLHttpRequest()
  
  xhr.open('PUT', url)
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')
  xhr.overrideMimeType(file.type);

  // Update progress (can be used to show progress indicator)
  xhr.upload.addEventListener("progress", function(e) {
    updateProgress(i, (e.loaded * 100.0 / e.total) || 100)
  })

  xhr.addEventListener('readystatechange', function(e) {
    if (xhr.readyState == 4 && xhr.status == 200) {
      updateProgress(i, 100) // <- Add this
    }
    else if (xhr.readyState == 4 && xhr.status != 200) {
      // Error. Inform the user
    }
  })

  xhr.send(file)
}
</script>
</body>
</html>
`