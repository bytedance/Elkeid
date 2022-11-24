package tos

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/bramvdbogaerde/go-scp"
)

type ScpClient struct {
	url []string
	dst string
	c   scp.Client
}

func (c *ScpClient) getURL(object string) (res []string) {
	for _, url := range c.url {
		res = append(res, url+object)
	}
	return
}
func (c *ScpClient) PutObject(ctx context.Context, object string, size int64, r io.Reader) ([]string, error) {
	err := c.c.Connect()
	if err != nil {
		return nil, err
	}
	err = c.c.CopyFile(ctx, r, filepath.Join(c.dst, object), "0655")
	if err != nil {
		return nil, err
	}
	return c.getURL(object), nil
}

type NginxClient struct {
	url    []string
	path   string
	domain string
	user   string
	passwd string
	c      *http.Client
}

func (c *NginxClient) getURL(object string) (res []string) {
	for _, url := range c.url {
		res = append(res, url+object)
	}
	return
}
func (c *NginxClient) PutObject(ctx context.Context, object string, size int64, r io.Reader) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%v%v", c.domain, filepath.Join(c.path, object)), r)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "binary/octet-stream")
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.user+":"+c.passwd)))
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return c.getURL(object), nil
}
func NewNginxClient(domain string, url []string, path string, user, passwd string) (*NginxClient, error) {
	return &NginxClient{url: url, path: path, domain: domain, c: &http.Client{}, user: user, passwd: passwd}, nil
}

type PlacehloderClient struct {
	url []string
	// remove prefix pattern
	rpre int
	// remove suffix pattern
	rsuf int
}

func (c *PlacehloderClient) getURL(object string) (res []string) {
	for _, url := range c.url {
		res = append(res, url+object)
	}
	return
}
func (c *PlacehloderClient) PutObject(ctx context.Context, object string, size int64, r io.Reader) ([]string, error) {
	splits := filepath.SplitList(object)
	if len(splits) > c.rsuf {
		splits = splits[:len(splits)-c.rsuf]
	}
	if len(splits) > c.rpre {
		splits = splits[c.rpre:]
	}
	return c.getURL(filepath.Join(splits...)), nil
}

type Client interface {
	PutObject(ctx context.Context, object string, size int64, r io.Reader) ([]string, error)
}

type Config struct {
	Host     string
	Port     string
	Url      []string
	Dst      string
	Username string
	KeyPath  string

	Type string

	Bucket   string
	Ak       string
	Sk       string
	Endpoint string
}
