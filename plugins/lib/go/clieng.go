//go:generate protoc --gogofaster_out=:. bridge.proto
package plugins

import (
	"bufio"
	"encoding/binary"
	io "io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type Client struct {
	rx     io.ReadCloser
	tx     io.WriteCloser
	reader *bufio.Reader
	writer *bufio.Writer
	rmu    *sync.Mutex
	wmu    *sync.Mutex
}

func New(ignore_terminate bool) (c *Client) {
	c = &Client{
		rx:     os.Stdin,
		tx:     os.Stdout,
		reader: bufio.NewReader(os.NewFile(3, "in_pipe")),
		writer: bufio.NewWriterSize(os.NewFile(4, "out_pipe"), 512*1024),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
	}
	go func() {
		ticker := time.NewTicker(time.Millisecond * 200)
		defer ticker.Stop()
		for {
			<-ticker.C
			c.wmu.Lock()
			if err := c.writer.Flush(); err != nil {
				c.wmu.Unlock()
				break
			}
			c.wmu.Unlock()
		}
	}()
	if ignore_terminate {
		go func() {
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGTERM)
			sig := <-sigs
			zap.S().Info("receive signal: %v, wait 3 secs to exit", sig.String())
			<-time.After(time.Second * 3)
			c.Close()
		}()
	}
	return
}
func (c *Client) SendRecord(rec *Record) (err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	size := rec.Size()
	err = binary.Write(c.writer, binary.LittleEndian, uint64(size))
	if err != nil {
		return
	}
	var buf []byte
	buf, err = rec.Marshal()
	if err != nil {
		return
	}
	_, err = c.writer.Write(buf)
	return
}
func (c *Client) ReceiveTask() (t *Task, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var len uint64
	err = binary.Read(c.reader, binary.LittleEndian, &len)
	if err != nil {
		return
	}
	var buf []byte
	buf, err = c.reader.Peek(int(len))
	if err != nil {
		return
	}
	t = &Task{}
	err = t.Unmarshal(buf)
	return
}
func (c *Client) Flush() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writer.Flush()
}

func (c *Client) Close() {
	c.writer.Flush()
	c.rx.Close()
	c.tx.Close()
}
