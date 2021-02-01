package util

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// NewZIPReader creates a io.ReadCloser that will read the given paths from disk and return a ZIP archive
// from them. The paths argument supports files and directories and will relativize paths accordingly.
func NewZIPReader(paths []string) (io.ReadCloser, error) {
	baseDir, relativeFiles, err := relativizeFiles(recursePaths(paths))
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		z := zip.NewWriter(pw)
		defer z.Close()

		for _, relativeFile := range relativeFiles {
			file := baseDir + string(os.PathSeparator) + relativeFile
			if err := addToZIP(z, relativeFile, file); err != nil {
				fmt.Fprintf(os.Stderr, "skipping due to error (4): %s\n", err.Error())
				continue
			}
		}
	}()

	return pr, nil
}

func recursePaths(paths []string) []string {
	files := make([]string, 0)
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping due to error (1): %s\n", err.Error())
			continue
		}
		if stat.IsDir() {
			filesInDir := make([]string, 0)
			err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					fmt.Fprintf(os.Stderr, "skipping due to error (2): %s\n", err.Error())
					return nil
				}
				if !info.IsDir() {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "skipping due to error (3): %s\n", err.Error())
				continue
			}
			files = append(files, filesInDir...)
		} else {
			files = append(files, path)
		}
	}
	return files
}

func addToZIP(z *zip.Writer, name string, file string) error {
	stat, err := os.Stat(file)
	if err != nil {
		return err
	}
	zf, err := z.CreateHeader(&zip.FileHeader{
		Name:     name,
		Modified: stat.ModTime(),
		Method:   zip.Deflate,
	})
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(zf, f); err != nil {
		return err
	}
	return nil
}

// ExtractZIP extracts the given ZIP archive at filename to a directory dir
func ExtractZIP(filename string, dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	z, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer z.Close()

	for _, zf := range z.File {
		filename := filepath.Join(dir, zf.Name)

		if !strings.HasPrefix(filename, filepath.Clean(dir)+string(os.PathSeparator)) {
			return &errInvalidZIPPath{filename} // ZipSlip, see https://snyk.io/research/zip-slip-vulnerability#go
		}

		if zf.FileInfo().IsDir() {
			os.MkdirAll(filename, 0755)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
			return err
		}
		outFile, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode())
		if err != nil {
			return err
		}
		entry, err := zf.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, entry)
		outFile.Close()
		entry.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type errInvalidZIPPath struct {
	filename string
}

func (e *errInvalidZIPPath) Error() string {
	return fmt.Sprintf("invalid ZIP path: %s", e.filename)
}
