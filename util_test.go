package pcopy

import (
	"os"
	"testing"
)

func TestCommonPrefix_1(t *testing.T) {
	paths := []string{
		"/home/phil/code/pcopy/go.mod",
		"/home/phil/code/pcopy/go.sum",
	}
	assertStrEquals(t, "/home/phil/code/pcopy", commonPrefix(paths))
}

func TestCommonPrefix_2(t *testing.T) {
	paths := []string{
		"/home/phil/code/pcopy/go.mod",
		"/home/phil/file.txt",
	}
	assertStrEquals(t, "/home/phil", commonPrefix(paths))
}

func TestCommonPrefix_3(t *testing.T) {
	paths := []string{
		"/home/phil/code/pcopy/go.mod",
		"/etc/file.txt",
	}
	assertStrEquals(t, "", commonPrefix(paths))
}

func TestRelativizePaths_AbsFilesOnly(t *testing.T) {
	files := []string{
		"/home/phil/code/pcopy/go.mod",
		"/home/phil/code/pcopy/go.sum",
		"/home/phil/code/fsdup/main.go",
	}
	baseDir, relativeFiles, err := relativizeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "/home/phil/code", baseDir)
	assertStrEquals(t, "pcopy/go.mod", relativeFiles[0])
	assertStrEquals(t, "pcopy/go.sum", relativeFiles[1])
	assertStrEquals(t, "fsdup/main.go", relativeFiles[2])
}

func TestRelativizePaths_AbsFilesNoCommonPrefix(t *testing.T) {
	files := []string{
		"/home/phil/code/pcopy/go.mod",
		"/etc/file.txt",
	}
	baseDir, relativeFiles, err := relativizeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "", baseDir)
	assertStrEquals(t, "home/phil/code/pcopy/go.mod", relativeFiles[0])
	assertStrEquals(t, "etc/file.txt", relativeFiles[1])
}

func TestRelativizePaths_OnlyRelFiles(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	files := []string{
		"some/file.txt",
		"other/file2.txt",
		"file3.txt",
	}
	baseDir, relativeFiles, err := relativizeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, tmpDir, baseDir)
	assertStrEquals(t, "some/file.txt", relativeFiles[0])
	assertStrEquals(t, "other/file2.txt", relativeFiles[1])
	assertStrEquals(t, "file3.txt", relativeFiles[2])
}

func TestRelativizePaths_RelAndAbsFiles(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	files := []string{
		"some/file.txt",
		"other/file2.txt",
		"/etc/pcopy/server.conf",
	}
	baseDir, relativeFiles, err := relativizeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "", baseDir)
	assertStrEquals(t, tmpDir[1:] + "/some/file.txt", relativeFiles[0])
	assertStrEquals(t, tmpDir[1:] + "/other/file2.txt", relativeFiles[1])
	assertStrEquals(t, "etc/pcopy/server.conf", relativeFiles[2])
}

