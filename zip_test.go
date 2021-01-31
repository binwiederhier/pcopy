package pcopy

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestZIP_ExtractZIPInvalidPath(t *testing.T) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	zf2, _ := z.Create("../../dir1/file.txt")
	zf2.Write([]byte("this is a nasty file"))
	z.Close()

	dir := t.TempDir()
	filename := filepath.Join(dir, "some.zip")
	os.WriteFile(filename, buf.Bytes(), 0600)

	dir2 := t.TempDir()
	err := extractZIP(filename, dir2)
	if _, ok := err.(*errInvalidZIPPath); !ok {
		t.Fatalf("expected errInvalidZIPPath, got none")
	}
}

func TestZIP_ExtractZIPRelativePath(t *testing.T) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	zf2, _ := z.Create("file.txt")
	zf2.Write([]byte("this is a perfectly fine file"))
	z.Close()

	dir := t.TempDir()
	filename := filepath.Join(dir, "some.zip")
	os.WriteFile(filename, buf.Bytes(), 0600)

	dir2 := t.TempDir()
	if err := os.Chdir(dir2); err != nil {
		t.Fatal(err)
	}
	if err := extractZIP(filename, "."); err != nil {
		t.Fatal(err)
	}
}

func TestZIP_ExtractZIPFileDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	if err := extractZIP("this does not exist", dir); err == nil {
		t.Fatalf("expected error, got none")
	}
}