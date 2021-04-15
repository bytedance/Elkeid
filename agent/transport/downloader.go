package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

func Download(u []string, d string, c string) error {
	hasher := sha256.New()
	file, err := os.Open(d)
	if err == nil {
		_, err := io.Copy(hasher, file)
		if err == nil {
			fileChecksum := hasher.Sum(nil)
			if hex.EncodeToString(fileChecksum[:]) == c {
				file.Close()
				return nil
			}
		}
		file.Close()
	}
	client := http.Client{Timeout: time.Second * 30}
	for _, url := range u {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		hasher.Reset()
		os.Remove(d)
		if file, err := os.OpenFile(d, os.O_RDWR|os.O_CREATE, 0700); err == nil {
			_, err = io.Copy(hasher, io.TeeReader(resp.Body, file))
			file.Close()
			if err != nil {
				zap.S().Error(err)
				os.Remove(d)
				continue
			}
			contentChecksum := hasher.Sum(nil)
			if hex.EncodeToString(contentChecksum[:]) != c {
				zap.S().Error("Checksum does not match")
				os.Remove(d)
				continue
			}
			return nil
		}
	}
	return errors.New("All urls tried failed")
}
