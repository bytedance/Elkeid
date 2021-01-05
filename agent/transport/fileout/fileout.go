package fileout

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/bytedance/ByteDance-HIDS/agent/spec"
	"github.com/bytedance/ByteDance-HIDS/agent/transport"
)

type FileOut struct {
	f *os.File
	w *bufio.Writer
}

func (fo *FileOut) Send(d *spec.Data) error {
	content, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = fo.w.Write(append(content, '\n'))
	if err != nil {
		return err
	}
	err = fo.w.Flush()
	if err != nil {
		return err
	}
	return nil
}

func (fo *FileOut) Receive() (spec.Task, error) {
	select {}
}

func (fo *FileOut) Close() {
	fo.w.Flush()
	fo.f.Close()
}

func NewFileOut(path string) (transport.Transport, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	return &FileOut{f, bufio.NewWriter(f)}, nil
}
