package zstd

import (
	"google.golang.org/grpc/encoding"
	"io"

	"github.com/DataDog/zstd"
)

const Name = "zstd"

func init() {
	c := &compressor{}
	encoding.RegisterCompressor(c)
}

func (c *compressor) Compress(w io.Writer) (io.WriteCloser, error) {
	z := zstd.NewWriter(w)
	return z, nil
}

func (c *compressor) Decompress(r io.Reader) (io.Reader, error) {
	z := zstd.NewReader(r)
	return z, nil
}

func (c *compressor) Name() string {
	return Name
}

type compressor struct {
}
