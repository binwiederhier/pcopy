package pcopy

import "io"

type Config struct {
	ListenAddr string
	CacheDir   string
	ServerUrl  string
	Key        string
}

type Client interface {
	Copy(reader io.Reader, fileId string) error
	Paste(writer io.Writer, fileId string) error
}