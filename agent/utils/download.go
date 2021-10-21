package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
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
	for _, rawurl := range config.DownloadUrls {
		var req *http.Request
		var resp *http.Response
		subctx, cancel := context.WithTimeout(ctx, time.Minute*3)
		defer cancel()
		req, err = http.NewRequestWithContext(subctx, "GET", rawurl, nil)
		if err != nil {
			continue
		}
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		var buf []byte
		buf, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		hasher.Reset()
		hasher.Write(buf)
		if !bytes.Equal(hasher.Sum(nil), checksum) {
			err = errors.New("checksum doesn't match")
			continue
		} else {
			br := bytes.NewBuffer(buf)
			switch config.Type {
			case "tar.gz":
				err = DecompressTarGz(dst, br)
			default:
				err = DecompressDefault(dst, br)
			}
			break
		}
	}
	return
}
