package pcopy

import (
	_ "embed" // Required for go:embed instructions
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

const (
	metaFileSuffix = ":meta"
)

type clipboard struct {
	dir string
}

func newClipboard(dir string) (*clipboard, error) {
	if unix.Access(dir, unix.W_OK) != nil {
		return nil, errClipboardDirNotWritable
	}
	return &clipboard{dir}, nil
}

func (c *clipboard) GetFilenames(id string) (string, string, error) {
	for _, reserved := range reservedFiles {
		if id == reserved {
			return "", "", errInvalidFileID
		}
	}
	file := fmt.Sprintf("%s/%s", c.dir, id)
	meta := fmt.Sprintf("%s/%s%s", c.dir, id, metaFileSuffix)
	return file, meta, nil
}

func (c *clipboard) DeleteFile(id string) error {
	file, metafile, err := c.GetFilenames(id)
	if err != nil {
		return err
	}
	if err := os.Remove(file); err != nil {
		return err
	}
	if err := os.Remove(metafile); err != nil {
		return err
	}
	return nil
}

func (c *clipboard) readMetaFile(metafile string) (*metaFile, error) {
	mf, err := os.Open(metafile)
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	var m metaFile
	if err := json.NewDecoder(mf).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *clipboard) writeMetaFile(metafile string, mode string, expires int64, reserved bool) error {
	response := &metaFile{
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
