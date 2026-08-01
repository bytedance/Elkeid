package transport

import (
	"errors"
	"strings"
	"testing"
)

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestReadUploadChunk(t *testing.T) {
	tests := []struct {
		name     string
		reader   *strings.Reader
		bufSize  int
		wantN    int
		wantDone bool
	}{
		{name: "full chunk", reader: strings.NewReader("data"), bufSize: 4, wantN: 4},
		{name: "final partial chunk", reader: strings.NewReader("data"), bufSize: 8, wantN: 4, wantDone: true},
		{name: "empty file", reader: strings.NewReader(""), bufSize: 8, wantDone: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.bufSize)
			n, done, err := readUploadChunk(tt.reader, buf)
			if err != nil {
				t.Fatalf("readUploadChunk() error = %v", err)
			}
			if n != tt.wantN || done != tt.wantDone {
				t.Fatalf("readUploadChunk() = (%d, %t), want (%d, %t)", n, done, tt.wantN, tt.wantDone)
			}
		})
	}
}

func TestReadUploadChunkPropagatesReadError(t *testing.T) {
	wantErr := errors.New("disk read failed")
	n, done, err := readUploadChunk(failingReader{err: wantErr}, make([]byte, 8))
	if !errors.Is(err, wantErr) {
		t.Fatalf("readUploadChunk() error = %v, want %v", err, wantErr)
	}
	if n != 0 || done {
		t.Fatalf("readUploadChunk() = (%d, %t), want (0, false)", n, done)
	}
}
