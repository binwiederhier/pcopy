package pcopy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

var _ Client = &client{}

type client struct {
	config *Config
}

func NewClient(config *Config) Client {
	return &client{
		config: config,
	}
}

func (c *client) Copy(reader io.Reader, fileId string) error {
	client := &http.Client{}
	url := fmt.Sprintf("%s/%s", c.config.ServerUrl, fileId)

	req, err := http.NewRequest(http.MethodPut, url, reader)
	if err != nil {
		return err
	}
	
	if _, err := client.Do(req); err != nil {
		return err
	}

	return nil
}

func (c *client) Paste(writer io.Writer, fileId string) error {
	client := &http.Client{}

	url := fmt.Sprintf("%s/%s", c.config.ServerUrl, fileId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	} else if resp.Body == nil {
		return errors.New("response body was empty")
	}

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}

	return nil
}

