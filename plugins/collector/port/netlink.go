package port

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// https://man7.org/linux/man-pages/man7/sock_diag.7.html
const (
	sizeofsockid       = 0x30
	sizeofinetDiagReq  = sizeofsockid + 0x8
	sizeofinetDiagResp = sizeofsockid + 0x18
)

type sockid struct {
	sport  uint16
	dport  uint16
	sip    net.IP
	dip    net.IP
	iface  uint32
	cookie [2]uint32
}
type inetDiagReq struct {
	family   uint8
	protocol uint8
	ext      uint8
	pad      uint8
	states   uint32
	id       sockid
}

func (r *inetDiagReq) Serialize() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, sizeofinetDiagReq))
	buf.WriteByte(r.family)
	buf.WriteByte(r.protocol)
	buf.WriteByte(r.ext)
	buf.WriteByte(r.pad)
	binary.Write(buf, nl.NativeEndian(), r.states)
	binary.Write(buf, binary.BigEndian, r.id.sport)
	binary.Write(buf, binary.BigEndian, r.id.dport)
	buf.Write(r.id.sip)
	if len(r.id.sip) < 16 {
		for i := 0; i < 16-len(r.id.sip); i++ {
			buf.WriteByte(0)
		}
	}
	buf.Write(r.id.dip)
	if len(r.id.dip) < 16 {
		for i := 0; i < 16-len(r.id.sip); i++ {
			buf.WriteByte(0)
		}
	}
	binary.Write(buf, nl.NativeEndian(), r.id.iface)
	binary.Write(buf, nl.NativeEndian(), r.id.cookie[0])
	binary.Write(buf, nl.NativeEndian(), r.id.cookie[1])
	return buf.Bytes()
}
func (r *inetDiagReq) Len() int { return sizeofinetDiagReq }

type inetDiagResp struct {
	family  uint8
	state   uint8
	timer   uint8
	retrans uint8
	id      sockid
	expires uint32
	rqueue  uint32
	wqueue  uint32
	uid     uint32
	inode   uint32
}

func (r *inetDiagResp) Deserialize(d []byte) (err error) {
	if len(d) < r.Len() {
		return fmt.Errorf("socket data short read %d, want %d", len(d), r.Len())
	}
	buf := bytes.NewBuffer(d)
	r.family, err = buf.ReadByte()
	if err != nil {
		return
	}
	r.state, err = buf.ReadByte()
	if err != nil {
		return
	}
	r.timer, err = buf.ReadByte()
	if err != nil {
		return
	}
	r.retrans, err = buf.ReadByte()
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.BigEndian, &r.id.sport)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.BigEndian, &r.id.dport)
	if err != nil {
		return
	}
	if r.family == unix.AF_INET6 {
		r.id.sip = net.IP(buf.Next(16))
		r.id.dip = net.IP(buf.Next(16))
	} else {
		r.id.sip = net.IP(buf.Next(4))
		buf.Next(12)
		r.id.dip = net.IP(buf.Next(4))
		buf.Next(12)
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.id.iface)
	if err != nil {
		return
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.id.cookie[0])
	if err != nil {
		return
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.id.cookie[1])
	if err != nil {
		return
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.expires)
	if err != nil {
		return
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.rqueue)
	if err != nil {
		return
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.wqueue)
	if err != nil {
		return
	}
	err = binary.Read(buf, nl.NativeEndian(), &r.uid)
	if err != nil {
		return
	}
	return binary.Read(buf, nl.NativeEndian(), &r.inode)
}
func (r *inetDiagResp) Len() int { return sizeofinetDiagResp }

func inetDiag(family, proto uint8) (ret []*inetDiagResp, err error) {
	var s *nl.NetlinkSocket
	s, err = nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return
	}
	defer s.Close()
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	var state uint32
	if proto == unix.IPPROTO_UDP {
		state = 7
	} else if proto == unix.IPPROTO_TCP {
		state = 10
	} else {
		err = fmt.Errorf("unsupported protocol %d", proto)
		return
	}
	req.AddData(&inetDiagReq{
		family:   family,
		protocol: proto,
		ext:      (1 << (netlink.INET_DIAG_VEGASINFO - 1)) | (1 << (netlink.INET_DIAG_INFO - 1)),
		states:   uint32(1 << state),
	})
	err = s.Send(req)
	if err != nil {
		return
	}
loop:
	for {
		var msgs []syscall.NetlinkMessage
		var from *unix.SockaddrNetlink
		msgs, from, err = s.Receive()
		if err != nil {
			return
		}
		if from.Pid != nl.PidKernel {
			continue
		}
		if len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				break loop
			case unix.NLMSG_ERROR:
				err = errors.New("unknown error")
				break loop
			}
			resp := &inetDiagResp{}
			if err := resp.Deserialize(m.Data); err != nil {
				continue
			}
			if resp.inode != 0 {
				ret = append(ret, resp)
			}
		}
	}
	return

}
