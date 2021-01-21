package pcopy

import (
	_ "embed" // Required for go:embed instructions
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

const (
	metaFileSuffix = ":meta"
)

var (
	reservedFiles = []string{"help", "version", "info", "verify", "static", "robots.txt", "favicon.ico"}
)

type clipboard struct {
	dir                 string
	fallbackExpireAfter time.Duration
}

type clipboardStats struct {
	NumFiles int
	Size     int64
}

// clipboardFile defines the metadata file format stored next to each file
type clipboardFile struct {
	ID       string `json:"-"`
	Size     int64 `json:"-"`
	ModTime  time.Time `json:"-"`
	Pipe     bool `json:"-"`
	Mode     string `json:"mode"`
	Expires  int64  `json:"expires"`
	Reserved bool   `json:"reserved"`
}

func newClipboard(dir string, expireAfter time.Duration) (*clipboard, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errClipboardDirNotWritable
	}
	if unix.Access(dir, unix.W_OK) != nil {
		return nil, errClipboardDirNotWritable
	}
	return &clipboard{dir, expireAfter}, nil
}

func (c *clipboard) IsValidID(id string) bool {
	// TODO include regex from server.go
	for _, reserved := range reservedFiles {
		if id == reserved {
			return false
		}
	}
	return true
}

func (c *clipboard) GetFilenames(id string) (string, string) {
	file := fmt.Sprintf("%s/%s", c.dir, id)
	return file, file + metaFileSuffix
}

func (c *clipboard) DeleteFile(id string) error {
	if !c.IsValidID(id) {
		return errInvalidFileID
	}
	file, metafile := c.GetFilenames(id)
	if err := os.Remove(file); err != nil {
		return err
	}
	if err := os.Remove(metafile); err != nil {
		return err
	}
	return nil
}

func (c *clipboard) Expire() (*clipboardStats, error) {
	entries, err := c.List()
	if err != nil {
		return nil, err
	}

	totalSize := int64(0)
	for _, e := range entries {
		c.maybeExpire(e)
		totalSize += e.Size
	}
	return &clipboardStats{len(entries), totalSize}, nil
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
	return &clipboardStats{len(entries), totalSize}, nil
}

func (c *clipboard) List() ([]*clipboardFile, error) {
	entries := make([]*clipboardFile, 0)
	files, err := ioutil.ReadDir(c.dir)
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
	if !c.IsValidID(id) {
		return nil, errInvalidFileID
	}

	file, metafile := c.GetFilenames(id)
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
		cf.Expires = int64(c.fallbackExpireAfter.Seconds())
	}
	cf.ID = id
	cf.Size = stat.Size()
	cf.ModTime = stat.ModTime()
	cf.Pipe = stat.Mode()&os.ModeNamedPipe == os.ModeNamedPipe

	return &cf, nil
}

func (c *clipboard) WriteMeta(id string, mode string, expires int64, reserved bool) error {
	if !c.IsValidID(id) {
		return errInvalidFileID
	}
	_, metafile := c.GetFilenames(id)
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

// maybeExpire deletes a file if it has expired and returns true if it did
func (c *clipboard) maybeExpire(entry *clipboardFile) bool {
	if entry.Expires == 0 || time.Until(time.Unix(entry.Expires, 0)) > 0 {
		return false
	}
	if err := c.DeleteFile(entry.ID); err != nil {
		log.Printf("failed to remove clipboard entry after expiry: %s", err.Error())
		return false
	}
	log.Printf("removed expired entry: %s (%s)", entry.ID, BytesToHuman(entry.Size))
	return true
}
