package pcopy

import (
	_ "embed" // Required for go:embed instructions
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
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
	reservedFiles = []string{"help", "version", "info", "verify", "random", "static", "robots.txt", "favicon.ico"}
)

type clipboard struct {
	config       *Config
	countLimiter *limiter
	sizeLimiter  *limiter
}

type clipboardStats struct {
	NumFiles int
	Size     int64
}

// clipboardFile defines the metadata file format stored next to each file
type clipboardFile struct {
	ID       string    `json:"-"`
	Size     int64     `json:"-"`
	ModTime  time.Time `json:"-"`
	Pipe     bool      `json:"-"`
	Mode     string    `json:"mode"`
	Expires  int64     `json:"expires"`
	Reserved bool      `json:"reserved"`
}

func newClipboard(config *Config) (*clipboard, error) {
	if err := os.MkdirAll(config.ClipboardDir, 0700); err != nil {
		return nil, errClipboardDirNotWritable
	}
	if unix.Access(config.ClipboardDir, unix.W_OK) != nil {
		return nil, errClipboardDirNotWritable
	}
	return &clipboard{
		config:       config,
		sizeLimiter:  newLimiter(config.ClipboardSizeLimit),
		countLimiter: newLimiter(int64(config.ClipboardCountLimit)),
	}, nil
}

func (c *clipboard) DeleteFile(id string) error {
	file, metafile, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	if err := os.Remove(metafile); err != nil {
		return err
	}
	if err := os.Remove(file); err != nil {
		return err
	}
	return nil
}

func (c *clipboard) Expire() error {
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
		log.Printf("removed expired entry: %s (%s)", entry.ID, BytesToHuman(entry.Size))
	}
	return nil
}

func (c *clipboard) Stats() (*clipboardStats, error) {
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
	return &clipboardStats{len(entries), totalSize}, nil
}

func (c *clipboard) List() ([]*clipboardFile, error) {
	entries := make([]*clipboardFile, 0)
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

func (c *clipboard) Stat(id string) (*clipboardFile, error) {
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

	var cf clipboardFile
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

func (c *clipboard) WriteMeta(id string, mode string, expires int64, reserved bool) error {
	_, metafile, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	response := &clipboardFile{
		Mode:     mode,
		Expires:  expires,
		Reserved: reserved,
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

func (c *clipboard) Add() error {
	return c.countLimiter.Add(1)
}

func (c *clipboard) WriteFile(id string, rc io.ReadCloser) error {
	file, _, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	fileSizeLimiter := newLimiter(c.config.FileSizeLimit)
	limitWriter := newLimitWriter(f, fileSizeLimiter, c.sizeLimiter)

	if _, err := io.Copy(limitWriter, rc); err != nil {
		c.DeleteFile(id)
		if pe, ok := err.(*fs.PathError); ok {
			err = pe.Err
		}
		if se, ok := err.(*os.SyscallError); ok {
			err = se.Err
		}
		if err == syscall.EPIPE {
			return errBrokenPipe
		}
		return err // most likely this is errLimitReached
	}
	if err := rc.Close(); err != nil {
		c.DeleteFile(id)
		return err
	}

	return nil
}

func (c *clipboard) MakePipe(id string) error {
	file, _, err := c.getFilenames(id)
	if err != nil {
		return err
	}
	return unix.Mkfifo(file, 0600)
}

func (c *clipboard) ReadFile(id string, w io.Writer) error {
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

func (c *clipboard) getFilenames(id string) (string, string, error) {
	if !c.isValidID(id) {
		return "", "", errInvalidFileID
	}
	file := fmt.Sprintf("%s/%s", c.config.ClipboardDir, id)
	return file, file + metaFileSuffix, nil
}

func (c *clipboard) isValidID(id string) bool {
	// TODO include regex from server.go
	for _, reserved := range reservedFiles {
		if id == reserved {
			return false
		}
	}
	return true
}

var errBrokenPipe = errors.New("broken pipe")
