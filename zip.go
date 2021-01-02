package pcopy

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func createZipReader(paths []string) (io.ReadCloser, error) {
	baseDir, relativeFiles, err := relativizeFiles(findAllFiles(paths))
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
			if err := addFileToZip(z, relativeFile, file); err != nil {
				fmt.Fprintf(os.Stderr, "skipping file %s due to error (5): %s\n", file, err.Error())
				continue
			}
		}
	}()

	return pr, nil
}

func findAllFiles(paths []string) []string {
	files := make([]string, 0)
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping file %s due to error (1): %s\n", path, err.Error())
			continue
		}
		if stat.IsDir() {
			filesInDir, err := findFilesRecursively(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skipping dir %s due to error (2): %s\n", path, err.Error())
			}
			files = append(files, filesInDir...)
		} else {
			files = append(files, path)
		}
	}
	return files
}

func findFilesRecursively(dir string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s due to error (3): %s\n", path, err.Error())
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func addFileToZip(z *zip.Writer, name string, file string) error {
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
