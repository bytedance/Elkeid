package main

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"

	"crypto/sha256"

	lru "github.com/hashicorp/golang-lru"
)

var hasherPool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}
var innerCache, _ = lru.NewARC(2048)

func GetSha256ByPath(path string) (shasum string, err error) {
	cacheShasum, ok := innerCache.Get(path)
	if ok {
		shasum = cacheShasum.(string)
		return
	}
	var f *os.File
	f, err = os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fstat, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fstat.Size() > 10*1024*1024 {
		return "", fmt.Errorf("File size is larger than max limitation:%v", fstat.Size())
	}
	hasher := hasherPool.Get().(hash.Hash)
	defer hasher.Reset()
	defer hasherPool.Put(hasher)
	_, err = io.Copy(hasher, f)
	if err != nil {
		return
	}
	shasum = hex.EncodeToString(hasher.Sum(nil))
	innerCache.Add(path, shasum)
	return
}
