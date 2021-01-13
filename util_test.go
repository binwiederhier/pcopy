package pcopy

import (
	"os"
	"testing"
	"time"
)

func TestExpandHome_WithTilde(t *testing.T) {
	assertStrEquals(t, os.Getenv("HOME")+"/this/is/a/path", ExpandHome("~/this/is/a/path"))
}

func TestExpandHome_NoTilde(t *testing.T) {
	assertStrEquals(t, "/this/is/an/absolute/path", ExpandHome("/this/is/an/absolute/path"))
}

func TestCollapseHome_HasHomePrefix(t *testing.T) {
	assertStrEquals(t, "~/this/is/a/path", CollapseHome(os.Getenv("HOME")+"/this/is/a/path"))
}

func TestCollapseHome_NoHomePrefix(t *testing.T) {
	assertStrEquals(t, "/this/is/an/absolute/path", CollapseHome("/this/is/an/absolute/path"))
}

func TestBytesToHuman_Small(t *testing.T) {
	assertStrEquals(t, "10 B", BytesToHuman(10))
}

func TestBytesToHuman_Large(t *testing.T) {
	assertStrEquals(t, "10.1 MB", BytesToHuman(10590617))
}

func TestCommonPrefix_Empty(t *testing.T) {
	var paths []string
	assertStrEquals(t, "", commonPrefix(paths))
}

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

func TestCommonPrefix_NoCommonPrefix(t *testing.T) {
	paths := []string{
		"/home/phil/code/pcopy/go.mod",
		"/etc/file.txt",
	}
	assertStrEquals(t, "", commonPrefix(paths))
}

func TestCommonPrefix_SingleFile(t *testing.T) {
	paths := []string{
		"/home/phil/code/pcopy",
	}
	assertStrEquals(t, "/home/phil/code/pcopy", commonPrefix(paths))
}

func TestRelativizePaths_Empty(t *testing.T) {
	var files []string
	baseDir, relativeFiles, err := relativizeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, "", baseDir)
	assertInt64Equals(t, 0, int64(len(relativeFiles)))
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
	assertStrEquals(t, tmpDir[1:]+"/some/file.txt", relativeFiles[0])
	assertStrEquals(t, tmpDir[1:]+"/other/file2.txt", relativeFiles[1])
	assertStrEquals(t, "etc/pcopy/server.conf", relativeFiles[2])
}

func TestRelativizePaths_SingleRelFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	files := []string{
		"dir/file.txt",
	}
	baseDir, relativeFiles, err := relativizeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	assertStrEquals(t, tmpDir+"/dir", baseDir)
	assertStrEquals(t, "file.txt", relativeFiles[0])
}

func TestDurationToHuman_MoreThanOneDay(t *testing.T) {
	d := 49 * time.Hour
	assertStrEquals(t, "2d1h", DurationToHuman(d))
}

func TestDurationToHuman_LessThanOneDay(t *testing.T) {
	d := 17*time.Hour + 15*time.Minute
	assertStrEquals(t, "17h15m", DurationToHuman(d))
}
