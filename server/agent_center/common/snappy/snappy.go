package snappy

// This code is based upon the gzip wrapper in github.com/grpc/grpc-go:
// https://github.com/grpc/grpc-go/blob/master/encoding/gzip/gzip.go

import (
	"io"
	"io/ioutil"
	"sync"

	snappylib "github.com/golang/snappy"
	"google.golang.org/grpc/encoding"
)

const Name = "snappy"

type compressor struct {
	poolCompressor   sync.Pool
	poolDecompressor sync.Pool
}

type writer struct {
	*snappylib.Writer
	pool *sync.Pool
}

type reader struct {
	*snappylib.Reader
	pool *sync.Pool
}

func init() {
	c := &compressor{}
	c.poolCompressor.New = func() interface{} {
		w := snappylib.NewWriter(ioutil.Discard)
		return &writer{Writer: w, pool: &c.poolCompressor}
	}
	encoding.RegisterCompressor(c)
}

func (c *compressor) Compress(w io.Writer) (io.WriteCloser, error) {
	z := c.poolCompressor.Get().(*writer)
	z.Writer.Reset(w)
	return z, nil
}

func (c *compressor) Decompress(r io.Reader) (io.Reader, error) {
	z, inPool := c.poolDecompressor.Get().(*reader)
	if !inPool {
		newR := snappylib.NewReader(r)
		return &reader{Reader: newR, pool: &c.poolDecompressor}, nil
	}
	z.Reset(r)
	return z, nil
}

func (c *compressor) Name() string {
	return Name
}

func (z *writer) Close() error {
	err := z.Writer.Close()
	z.pool.Put(z)
	return err
}

func (z *reader) Read(p []byte) (n int, err error) {
	n, err = z.Reader.Read(p)
	if err == io.EOF {
		z.pool.Put(z)
	}
	return n, err
}
