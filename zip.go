package pcopy

import (
	"archive/zip"
	"io"
	"log"
	"os"
	"path/filepath"
)

func createZipReader(files []string) io.ReadCloser {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		z := zip.NewWriter(pw)
		defer z.Close()

		for _, file := range files {
			stat, err := os.Stat(file)
			if err != nil {
				log.Printf("Skipping file %s due to error: %s\n", file, err.Error())
				continue
			}

			if stat.IsDir() {
				if err := walkDirAndAddFilesToZip(z, file); err != nil {
					log.Printf("Skipping directory %s due to error: %s\n", file, err.Error())
					continue
				}
			} else {
				if err := addFileToZip(z, file, stat); err != nil {
					log.Printf("Skipping file %s due to error: %s\n", file, err.Error())
					continue
				}
			}
		}
	}()

	return pr
}

func addFileToZip(z *zip.Writer, file string, stat os.FileInfo) error {
	zf, err := z.CreateHeader(&zip.FileHeader{
		Name:     file,
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

func walkDirAndAddFilesToZip(z *zip.Writer, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Skipping %s due to error: %s\n", path, err.Error())
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if err := addFileToZip(z, path, info); err != nil {
			log.Printf("Cannot add %s due to error: %s\n", path, err.Error())
			return nil
		}
		return nil
	})
}
