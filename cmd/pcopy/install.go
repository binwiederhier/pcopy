package main

import (
	"os"
	"pcopy"
)

func execInstall() {
	executable, err := pcopy.GetExecutable()
	if err != nil {
		fail(err)
	}

	if _, err := os.Stat("/usr/bin/pcp"); err != nil {
		if err := os.Symlink(executable, "/usr/bin/pcp"); err != nil {
			fail(err)
		}
	}

	if _, err := os.Stat("/usr/bin/ppaste"); err != nil {
		if err := os.Symlink(executable, "/usr/bin/ppaste"); err != nil {
			fail(err)
		}
	}
}
