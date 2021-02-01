package clipboard

import (
	_ "embed" // Required for go:embed instructions
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/util"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	metaFileSuffix = ":meta"
)

var (
	// ErrBrokenPipe is returned when the target file is a pipe and the consumer prematurely interrupts reading
	ErrBrokenPipe = errors.New("broken pipe")

	// ErrInvalidFileID is returned in any method that deals with file ID input for reserved identifiers (ReadFile, WriteFile, ...)
	ErrInvalidFileID = errors.New("invalid file id")

	reservedFiles              = []string{"help", "version", "info", "verify", "random", "static", "robots.txt", "favicon.ico"}
	errClipboardDirNotWritable = errors.New("clipboard dir not writable by user")
)

// Clipboard is responsible for storing files on the file system. In addition to storage, it also takes care
// of expiring files, and of limiting total clipboard size and count.
type Clipboard struct {
	config       *config.Config
	countLimiter *util.Limiter
	sizeLimiter  *util.Limiter
}

// Stats holds statistics about the current clipboard usage
type Stats struct {
	NumFiles int
	Size     int64
}

// File defines the metadata file format stored next to each file
type File struct {
	ID      string    `json:"-"`
	Size    int64     `json:"-"`
	ModTime time.Time `json:"-"`
	Pipe    bool      `json:"-"`
	Mode    string    `json:"mode"`
	Expires int64     `json:"expires"`
}

// New creates a new Clipboard using the given config
func New(config *config.Config) (*Clipboard, error) {
	if err := os.MkdirAll(config.ClipboardDir, 0700); err != nil {
		return nil, errClipboardDirNotWritable
	}
	if unix.Access(config.ClipboardDir, unix.W_OK) != nil {
		return nil, errClipboardDirNotWritable
	}
	return &Clipboard{
		config:       config,
		sizeLimiter:  util.NewLimiter(config.ClipboardSizeLimit),
		countLimiter: util.NewLimiter(int64(config.ClipboardCountLimit)),
	}, nil
}

// DeleteFile removes the file with the given ID from the clipboard, including its metadata file
func (c *Clipboard) DeleteFile(id string) error {
	file, metafile, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	err1 := os.Remove(metafile)
	err2 := os.Remove(file)
	if err1 != nil {
		return err1
	} else if err2 != nil {
		return err2
	}
	return nil
}

// Expire will use List to list all clipboard entries and delete the ones that have expired
func (c *Clipboard) Expire() error {
	entries, err := c.List()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Expires == 0 || time.Until(time.Unix(entry.Expires, 0)) > 0 {
			continue
		}
		if err := c.DeleteFile(entry.ID); err != nil {
			log.Printf("failed to remove clipboard entry after expiry: %s", err.Error())
			continue
		}
		log.Printf("removed expired entry: %s (%s)", entry.ID, util.BytesToHuman(entry.Size))
	}
	return nil
}

// Stats returns statistics about the current clipboard. It also updates the limiters with the current
// cumulative values.
func (c *Clipboard) Stats() (*Stats, error) {
	entries, err := c.List()
	if err != nil {
		return nil, err
	}
	totalSize := int64(0)
	for _, f := range entries {
		totalSize += f.Size
	}
	c.countLimiter.Set(int64(len(entries)))
	c.sizeLimiter.Set(totalSize)
	return &Stats{len(entries), totalSize}, nil
}

// List returns a metadata about the files in the clipboard
func (c *Clipboard) List() ([]*File, error) {
	entries := make([]*File, 0)
	files, err := ioutil.ReadDir(c.config.ClipboardDir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), metaFileSuffix) {
			cf, err := c.Stat(f.Name())
			if err != nil {
				log.Printf("error reading metadata for %s: %s", f.Name(), err.Error())
				continue
			}
			entries = append(entries, cf)
		}
	}
	return entries, nil
}

// Stat returns metadata about a file in a clipboard
func (c *Clipboard) Stat(id string) (*File, error) {
	file, metafile, err := c.getFilenames(id)
	if err != nil {
		return nil, err
	}
	stat, err := os.Stat(file)
	if err != nil {
		return nil, err
	}

	mf, err := os.Open(metafile)
	if err != nil {
		c.DeleteFile(id) // A file without a metafile is undesired!
		return nil, err
	}
	defer mf.Close()

	var cf File
	if err := json.NewDecoder(mf).Decode(&cf); err != nil {
		log.Printf("error reading meta file for %s: %s", id, err.Error())
		cf.Expires = int64(c.config.FileExpireAfter.Seconds())
	}
	cf.ID = id
	cf.Size = stat.Size()
	cf.ModTime = stat.ModTime()
	cf.Pipe = stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe

	return &cf, nil
}

// WriteMeta writes files metadata for the given clipboard entry
func (c *Clipboard) WriteMeta(id string, mode string, expires int64) error {
	_, metafile, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	response := &File{
		Mode:    mode,
		Expires: expires,
	}
	mf, err := os.OpenFile(metafile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer mf.Close()
	if err := json.NewEncoder(mf).Encode(response); err != nil {
		return err
	}
	return nil
}

// Allow increases the clipboard file counter and returns true if a new file may be added
func (c *Clipboard) Allow() bool {
	err := c.countLimiter.Add(1)
	return err == nil
}

// WriteFile writes the entire content of rc to the clipboard entry. This method observes the
// per-file size limit as defined in the config, as well as the total clipboard size limit. If a limit is
// reached, it will return util.ErrLimitReached. When the target file is a FIFO pipe (see MakePipe) and the
// consumer prematurely interrupts reading, ErrBrokenPipe may be returned.
func (c *Clipboard) WriteFile(id string, rc io.ReadCloser) error {
	file, _, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	fileSizeLimiter := util.NewLimiter(c.config.FileSizeLimit)
	limitWriter := util.NewLimitWriter(f, fileSizeLimiter, c.sizeLimiter)

	if _, err := io.Copy(limitWriter, rc); err != nil {
		c.DeleteFile(id)
		if pe, ok := err.(*fs.PathError); ok {
			err = pe.Err
		}
		if se, ok := err.(*os.SyscallError); ok {
			err = se.Err
		}
		if err == syscall.EPIPE {
			return ErrBrokenPipe
		}
		return err // most likely this is errLimitReached

	}
	if err := rc.Close(); err != nil {
		c.DeleteFile(id)
		return err
	}

	return nil
}

// MakePipe creates a FIFO pipe that can be used for streaming
func (c *Clipboard) MakePipe(id string) error {
	file, _, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	return unix.Mkfifo(file, 0600)
}

// ReadFile reads the file content from the clipboard and writes it to w
func (c *Clipboard) ReadFile(id string, w io.Writer) error {
	file, _, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(w, f)
	return err
}

func (c *Clipboard) getFilenames(id string) (string, string, error) {
	if !c.isValidID(id) {
		return "", "", ErrInvalidFileID
	}
	file := fmt.Sprintf("%s/%s", c.config.ClipboardDir, id)
	return file, file + metaFileSuffix, nil
}

func (c *Clipboard) isValidID(id string) bool {
	// TODO include regex from server.go
	for _, reserved := range reservedFiles {
		if id == reserved {
			return false
		}
	}
	return true
}
