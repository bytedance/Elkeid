package utils

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/jellydator/ttlcache/v3"
	"github.com/juju/ratelimit"
)

var (
	mp = sync.Pool{
		New: func() interface{} { return md5.New() },
	}
	hp = sync.Pool{
		New: func() interface{} { return xxhash.New() },
	}
	rp = sync.Pool{
		New: func() interface{} {
			return bufio.NewReaderSize(nil, 1024*1024)
		},
	}
	mc = ttlcache.New(ttlcache.WithTTL[string, string](12*time.Hour), ttlcache.WithCapacity[string, string](2048))
	hc = ttlcache.New(ttlcache.WithTTL[string, string](12*time.Hour), ttlcache.WithCapacity[string, string](2048))
)

func init() {
	go mc.Start()
	go hc.Start()
}
func caculateMd5(f *os.File) (ret string, err error) {
	r := rp.Get().(*bufio.Reader)
	defer r.Reset(nil)
	defer rp.Put(r)
	h := mp.Get().(hash.Hash)
	defer h.Reset()
	defer mp.Put(h)
	var s fs.FileInfo
	s, err = f.Stat()
	if err != nil {
		return
	}
	if s.Size() > 100*1024*1024 {
		err = fmt.Errorf("file size is larger than limitation: %v", s.Size())
		return
	}
	r.Reset(f)
	lr := ratelimit.Reader(r, ratelimit.NewBucketWithRate(1024*1024, 1024*1024))
	_, err = io.Copy(h, lr)
	if err != nil {
		return
	}
	ret = hex.EncodeToString(h.Sum(nil))
	return
}
func GetMd5(path string, procPath string) (ret string, err error) {
	if cr := mc.Get(path); cr != nil {
		ret = cr.Value()
		return
	}
	defer func() {
		if err == nil {
			mc.Set(path, ret, time.Hour*12+time.Duration(rand.Intn(60*12))*time.Minute)
		}
	}()
	var f *os.File
	f, err = os.Open(path)
	if err == nil {
		ret, err = caculateMd5(f)
		f.Close()
		return
	}
	if procPath == "" {
		return
	}
	f, err = os.Open(procPath)
	if err != nil {
		return
	}
	ret, err = caculateMd5(f)
	f.Close()
	return
}

func caculateHash(f *os.File) (ret string, err error) {
	r := rp.Get().(*bufio.Reader)
	defer r.Reset(nil)
	defer rp.Put(r)
	h := hp.Get().(hash.Hash)
	defer h.Reset()
	defer hp.Put(h)
	var s fs.FileInfo
	s, err = f.Stat()
	if err != nil {
		return
	}
	err = binary.Write(h, binary.LittleEndian, uint64(s.Size()))
	if err != nil {
		return
	}
	r.Reset(f)
	lr := io.LimitReader(r, 32*1024)
	_, err = io.Copy(h, lr)
	if err != nil {
		return
	}
	ret = hex.EncodeToString(h.Sum(nil))
	return
}
func GetHash(path string, procPath string) (ret string, err error) {
	if cr := hc.Get(path); cr != nil {
		ret = cr.Value()
		return
	}
	defer func() {
		if err == nil {
			hc.Set(path, ret, time.Hour*12+time.Duration(rand.Intn(60*12))*time.Minute)
		}
	}()
	var f *os.File
	f, err = os.Open(path)
	if err == nil {
		ret, err = caculateHash(f)
		f.Close()
		return
	}
	if procPath == "" {
		return
	}
	f, err = os.Open(procPath)
	if err != nil {
		return
	}
	defer f.Close()
	ret, err = caculateHash(f)
	f.Close()
	return
}
