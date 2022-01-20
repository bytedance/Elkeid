package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

var hasherPool = sync.Pool{
	New: func() interface{} {
		return md5.New()
	},
}
var innerCache, _ = lru.NewARC(1024 * 5)

// func GetSha256ByPath(path string) (shasum string, err error) {
// 	cacheShasum, ok := innerCache.Get(path)
// 	if ok {
// 		shasum = cacheShasum.(string)
// 		return
// 	}
// 	var f *os.File
// 	f, err = os.Open(path)
// 	if err != nil {
// 		return
// 	}
// 	defer f.Close()
// 	fstat, err := f.Stat()
// 	if err != nil {
// 		return "", err
// 	}
// 	if fstat.Size() > 10*1024*1024 {
// 		return "", fmt.Errorf("File size is larger than max limitation:%v", fstat.Size())
// 	}
// 	hasher := hasherPool.Get().(hash.Hash)
// 	defer hasher.Reset()
// 	defer hasherPool.Put(hasher)
// 	_, err = io.Copy(hasher, f)
// 	if err != nil {
// 		return
// 	}
// 	shasum = hex.EncodeToString(hasher.Sum(nil))
// 	innerCache.Add(path, shasum)
// 	return
// }
func GetMd5ByPath(path string) (checksum string, err error) {
	cacheShasum, ok := innerCache.Get(path)
	if ok {
		checksum = cacheShasum.(string)
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
	if fstat.Size() > 15*1024*1024 {
		return "", fmt.Errorf("file size is larger than limitation:%v", fstat.Size())
	}
	hasher := hasherPool.Get().(hash.Hash)
	defer hasher.Reset()
	defer hasherPool.Put(hasher)
	_, err = io.Copy(hasher, f)
	if err != nil {
		return
	}
	checksum = hex.EncodeToString(hasher.Sum(nil))
	innerCache.Add(path, checksum)
	return
}
