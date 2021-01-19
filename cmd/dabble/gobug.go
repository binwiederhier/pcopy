package main

import (
	"bufio"
	"fmt"
	"github.com/valyala/fasthttp"
	"io"
	"net/http"
	"time"
)

type rdr struct {
	count int
}

func (r *rdr) Read(p []byte) (int, error) {
	if r.count > 500 {
		println("read end")
		return 0, io.EOF
	} else {
		//time.Sleep(time.Second)
		println("read")
		r.count++
		return len(p), nil
	}
}

func (r *rdr) Close() error {
	return nil
}


func main() {



	c := &http.Client{}
	req, _ := http.NewRequest(http.MethodPut, "http://localhost:1234/abc", &rdr{})
	req.Header.Set("X-Stream", "yes")
	println("before do")
	resp, _ := c.Do(req)
	println("after do")

	//fmt.Printf("%#v\n", resp)


	req := fasthttp.AcquireRequest()
	req.SetRequestURI("http://localhost:1234/abc")
	req.Header.SetMethod("PUT")
	//req.Header.Set("X-Stream", "yes")

	req.SetBodyStreamWriter(func(w *bufio.Writer) {
		for i := 0; i < 500; i++ {
			print(".")
			fmt.Fprintf(w, "this is a message number %d\n", i)

			// Do not forget flushing streamed data to the client.
			if err := w.Flush(); err != nil {
				return
			}
			//time.Sleep(time.Millisecond * 100)
		}
		for i := 501; i < 510; i++ {
			print("x")
			fmt.Fprintf(w, "this is a message number %d\n", i)

			// Do not forget flushing streamed data to the client.
			if err := w.Flush(); err != nil {
				return
			}
			time.Sleep(time.Millisecond * 100)
		}
	})

	resp := fasthttp.AcquireResponse()
	resp.ImmediateHeaderFlush = true

	c := &fasthttp.Client{}

	go func() {
		println("before do")
		if err := c.Do(req, resp); err != nil {
			panic(err)
		}
		println("after do")
	}()


	for {
		fmt.Printf("%#v\n\n", string(resp.Header.Peek("X-Url")))
		time.Sleep(time.Second)
	}
}
