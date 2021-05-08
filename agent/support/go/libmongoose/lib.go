package libmongoose

import (
	"net"
	"os"

	"github.com/tinylib/msgp/msgp"
)

type Client struct {
	name   string
	conn   net.Conn
	writer *msgp.Writer
	reader *msgp.Reader
}

func (c *Client) Receive() (*Task, error) {
	t := &Task{}
	err := t.DecodeMsg(c.reader)
	return t, err
}

func (c *Client) Send(d Data) error {
	err := d.EncodeMsg(c.writer)
	if err != nil {
		return err
	}
	err = c.writer.Flush()
	return err
}
func (c *Client) Close() {
	c.conn.Close()
}

func Connect(addr, name, version string) (*Client, error) {
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, err
	}
	w := msgp.NewWriter(conn)
	req := RegistRequest{Pid: uint32(os.Getpid()), Name: name, Version: version}
	err = req.EncodeMsg(w)
	if err != nil {
		return nil, err
	}
	err = w.Flush()
	if err != nil {
		return nil, err
	}
	return &Client{name, conn, w, msgp.NewReader(conn)}, nil
}
