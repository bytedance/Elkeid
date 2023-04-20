package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bytedance/Elkeid/agent/proto"
)

func CheckSignature(dst string, sign string) (err error) {
	var f *os.File
	f, err = os.Open(dst)
	if err != nil {
		return
	}
	var signBytes []byte
	signBytes, err = hex.DecodeString(sign)
	if err != nil {
		return
	}
	hasher := sha256.New()
	if err == nil {
		_, err = io.Copy(hasher, f)
		if err != nil {
			return
		}
		if !bytes.Equal(hasher.Sum(nil), signBytes) {
			err = errors.New("signature doesn't match")
			return
		}
		f.Chmod(0o0700)
		f.Close()
	}
	return
}

func Download(ctx context.Context, dst string, config proto.Config) (err error) {
	var checksum []byte
	checksum, err = hex.DecodeString(config.Sha256)
	if err != nil {
		return
	}
	hasher := sha256.New()
	var f *os.File
	f, err = os.Open(dst)
	if err == nil {
		_, err = io.Copy(hasher, f)
		if err == nil && bytes.Equal(hasher.Sum(nil), checksum) {
			f.Close()
			return
		}
		f.Close()
	}
	err = os.MkdirAll(filepath.Dir(dst), 0o0701)
	if err != nil {
		return
	}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: time.Minute * 10,
	}
	for _, rawurl := range config.DownloadUrls {
		var req *http.Request
		var resp *http.Response
		subctx, cancel := context.WithCancel(ctx)
		defer cancel()
		req, err = http.NewRequestWithContext(subctx, "GET", rawurl, nil)
		if err != nil {
			continue
		}
		resp, err = client.Do(req)
		if err != nil {
			continue
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			err = errors.New("http error: " + resp.Status)
			continue
		}
		resp.Body = http.MaxBytesReader(nil, resp.Body, 512*1024*1024)
		hasher.Reset()
		r := io.TeeReader(resp.Body, hasher)
		switch config.Type {
		case "tar.gz":
			err = DecompressTarGz(r, filepath.Dir(dst))
		default:
			f, err = os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0700)
			if err == nil {
				_, err = io.Copy(f, r)
				f.Close()
			}
		}
		resp.Body.Close()
		if err == nil {
			if checksum := hex.EncodeToString(hasher.Sum(nil)); checksum != config.Sha256 {
				err = fmt.Errorf("checksum doesn't match: %s vs %s", checksum, config.Sha256)
			} else {
				break
			}
		}
	}
	return
}
