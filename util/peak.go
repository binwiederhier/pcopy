package util

import (
	"bytes"
	"io"
	"strings"
)

type PeakedReadCloser struct {
	Peaked       []byte
	LimitReached bool
	peaked       io.Reader
	underlying   io.ReadCloser
	read         int
}

func Peak(underlying io.ReadCloser, limit int) (*PeakedReadCloser, error) {
	if underlying == nil {
		underlying = io.NopCloser(strings.NewReader(""))
	}
	prc := &PeakedReadCloser{
		underlying: underlying,
	}
	peaked := make([]byte, limit)
	read, err := underlying.Read(peaked)
	if err != nil && err != io.EOF {
		return nil, err
	}
	prc.peaked = bytes.NewReader(peaked[:read])
	prc.Peaked = peaked[:read]
	prc.LimitReached = read == limit
	return prc, nil
}

func (r *PeakedReadCloser) Read(p []byte) (n int, err error) {
	n, err = r.peaked.Read(p)
	if err == io.EOF {
		return r.underlying.Read(p)
	} else if err != nil {
		return 0, err
	}
	return
}

func (r *PeakedReadCloser) Close() error {
	return r.underlying.Close()
}
