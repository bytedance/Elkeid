package plugins

import (
	"bufio"
	"os"
	"sync"
	"time"
)

func New() (c *Client) {
	c = &Client{
		rx: os.Stdin,
		tx: os.Stdout,
		// MAX_SIZE = 1 MB
		reader: bufio.NewReaderSize(os.NewFile(3, "pipe"), 1024*1024),
		writer: bufio.NewWriterSize(os.NewFile(4, "pipe"), 512*1024),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
	}
	go func() {
		ticker := time.NewTicker(time.Millisecond * 200)
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := c.Flush(); err != nil {
				break
			}
		}
	}()
	return
}
