package compressor

import (
	"io"
	"sync"

	"github.com/golang/snappy"
	"google.golang.org/grpc/encoding"
)

const Name = "snappy"

type compressor struct {
	ws sync.Pool
	rs sync.Pool
}
type writer struct {
	*snappy.Writer
	pool *sync.Pool
}

func (w *writer) Close() error {
	defer w.pool.Put(w)
	return w.Writer.Close()
}

type reader struct {
	*snappy.Reader
	pool *sync.Pool
}

func (r *reader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err == io.EOF {
		r.pool.Put(r)
	}
	return n, err
}

func (c *compressor) Compress(w io.Writer) (io.WriteCloser, error) {
	wc := c.ws.Get().(*writer)
	wc.Reset(w)
	return wc, nil
}

func (c *compressor) Decompress(r io.Reader) (io.Reader, error) {
	rd := c.rs.Get().(*reader)
	rd.Reset(r)
	return rd, nil
}
func (c *compressor) Name() string {
	return Name
}

func init() {
	c := &compressor{}
	c.ws.New = func() interface{} {
		return &writer{
			Writer: snappy.NewBufferedWriter(io.Discard),
			pool:   &c.ws,
		}
	}
	c.rs.New = func() interface{} {
		return &reader{
			Reader: snappy.NewReader(nil),
			pool:   &c.rs,
		}
	}
	encoding.RegisterCompressor(c)
}
