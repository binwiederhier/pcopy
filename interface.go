package pcopy

import "io"

type Config struct {
	ListenAddr string
	KeyFile    string
	CertFile   string
	CacheDir   string

	ServerAddr string
	Key        string
}

type Client interface {
	Join() (string, error)
	Copy(reader io.Reader, fileId string) error
	Paste(writer io.Writer, fileId string) error
}