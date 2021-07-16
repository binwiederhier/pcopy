package server

import (
	"bytes"
	"heckel.io/pcopy/clipboard/clipboardtest"
	"heckel.io/pcopy/config"
	"heckel.io/pcopy/config/configtest"
	"heckel.io/pcopy/crypto"
	"heckel.io/pcopy/test"
	"heckel.io/pcopy/util"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"testing"
	"time"
)

func TestTCPForwarder_Help(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "echo help | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	test.StrContains(t, stdout.String(), `This is is the netcat-endpoint for pcopy`)

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_Basic(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "echo hi there | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	println(stdout.String())
	matches := regexp.MustCompile(`https://localhost:12345/(\S+)`).FindStringSubmatch(stdout.String())
	req, _ := http.NewRequest(http.MethodGet, matches[0], nil)

	test.StrContains(t, stdout.String(), `https://localhost:12345/`)
	clipboardtest.Content(t, conf, matches[1], "hi there\n")

	rr := httptest.NewRecorder()
	server.Handle(rr, req)
	test.StrEquals(t, rr.Body.String(), "hi there\n")

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithOptions(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "(echo \"pcopy:my-id?t=10m\"; echo hi there) | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	test.StrContains(t, stdout.String(), "https://localhost:12345/my-id")
	test.StrContains(t, stdout.String(), "valid for 10m")
	clipboardtest.Content(t, conf, "my-id", "hi there\n")

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithInvalidOptions(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "(echo \"pcopy://my-id?t=10m\"; echo hi there) | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	test.StrEquals(t, "Bad Request\n", stdout.String())
	clipboardtest.NotExist(t, conf, "my-id")

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithLimitFailure(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.FileSizeLimit = 5
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "echo 123456 | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	test.StrEquals(t, "Request Entity Too Large\n", stdout.String())

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithPasswordProtectedClipboard(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.Key, _ = crypto.GenerateKey([]byte("this is a password"))
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "(echo \"pcopy:sup?a=this+is+a+password\"; echo -n something) | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	test.StrContains(t, stdout.String(), "https://localhost:12345/sup?a=")
	clipboardtest.Content(t, conf, "sup", "something")

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithPasswordProtectedClipboardInvalidPass(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.Key, _ = crypto.GenerateKey([]byte("this is a password"))
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "(echo \"pcopy:sup?a=INVALID\"; echo -n something) | nc -N localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	clipboardtest.NotExist(t, conf, "sup")
	test.StrEquals(t, "Unauthorized\n", stdout.String())

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithTimeoutWithoutNParam(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12386", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	forwarder.ReadTimeout = time.Second // GitHub Actions is slowww...
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12386")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "(echo pcopy:test; echo 123; echo 456) | nc localhost 12386")
	cmd.Stdout = &stdout
	cmd.Run()

	clipboardtest.Content(t, conf, "test", "123\n456\n")

	forwarder.shutdown()
	test.WaitForPortDown(t, "12386")
}

func TestTCPForwarder_WithTimeoutWithoutNParamContentCutoff(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	server := newTestServer(t, conf)
	forwarder := newTCPForwarder(":12387", config.ExpandServerAddr(conf.ServerAddr), server.Handle)
	forwarder.ReadTimeout = time.Second // GitHub Actions is slowww...
	go forwarder.listenAndServe()
	test.WaitForPortUp(t, "12387")

	var stdout bytes.Buffer
	cmd := exec.Command("sh", "-c", "(echo pcopy:test; echo 123; sleep 2; echo 456) | nc localhost 12387")
	cmd.Stdout = &stdout
	cmd.Run()

	clipboardtest.Content(t, conf, "test", "123\n")

	forwarder.shutdown()
	test.WaitForPortDown(t, "12387")
}

func TestTCPForwarder_Stream(t *testing.T) {
	_, conf := configtest.NewTestConfig(t)
	conf.ServerAddr = "localhost:11443"
	conf.ListenHTTP = ":11080"
	conf.ListenHTTPS = ":11443"
	conf.ListenTCP = ":19999"
	serverRouter := startTestServerRouter(t, conf)
	test.WaitForPortUp(t, "11443")
	test.WaitForPortUp(t, "11080")
	test.WaitForPortUp(t, "19999")

	cmd := exec.Command("sh", "-c", "(echo \"pcopy:?s=1\"; echo 123) | nc -N localhost 19999")
	stdoutPipe, _ := cmd.StdoutPipe()
	cmd.Start()
	out := test.WaitForOutput(t, stdoutPipe, 1*time.Second, 100*time.Millisecond)

	pasteURL := regexp.MustCompile(`https://localhost\S+`).FindStringSubmatch(out)
	cert, _ := crypto.LoadCertFromFile(conf.CertFile)
	client, _ := util.NewHTTPClientWithPinnedCert(cert)
	resp, _ := client.Get(pasteURL[0])
	bodyBytes, _ := io.ReadAll(resp.Body)

	test.StrEquals(t, "123\n", string(bodyBytes))

	serverRouter.Stop()
	test.WaitForPortDown(t, "11443")
	test.WaitForPortDown(t, "11080")
	test.WaitForPortDown(t, "19999")
}
