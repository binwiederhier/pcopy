package cmd

import (
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/test"
	"testing"
)

func TestCLI_Link(t *testing.T) {
	filename, config := configtest.NewTestConfig(t)
	serverRouter := startTestServerRouter(t, config)
	defer serverRouter.Stop()

	test.WaitForPortUp(t, "12345")

	app, stdin, _, stderr := newTestApp()
	stdin.WriteString("test stdin")

	if err := Run(app, "pcp", "-c", filename, "some-file"); err != nil {
		t.Fatal(err)
	}
	clipboardtest.Content(t, config, "some-file", "test stdin")

	stderr.Reset()
	if err := Run(app, "pcopy", "link", "-c", filename, "some-file"); err != nil {
		t.Fatal(err)
	}
	test.StrContains(t, stderr.String(), "Direct link (valid for")
	test.StrContains(t, stderr.String(), "ppaste some-file")
	test.StrContains(t, stderr.String(), "curl -sSLk --pinnedpubkey")
	test.StrContains(t, stderr.String(), "https://localhost:12345/some-file")
}
