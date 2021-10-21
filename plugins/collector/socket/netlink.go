package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// SocketID identifies a single socket.
type _socketID struct {
	sourcePort      uint16
	destinationPort uint16
	source          net.IP
	destination     net.IP
	_interface      uint32
	cookie          [2]uint32
}

// Socket represents a netlink socket.
type _socket struct {
	family  uint8
	state   uint8
	timer   uint8
	retrans uint8
	id      _socketID
	expires uint32
	rQueue  uint32
	wQueue  uint32
	uid     uint32
	inode   uint32
}

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
)

var (
	native       = nl.NativeEndian()
	networkOrder = binary.BigEndian
)

type socketRequest struct {
	family   uint8
	protocol uint8
	ext      uint8
	pad      uint8
	states   uint32
	id       _socketID
}

type writeBuffer struct {
	Bytes []byte
	pos   int
}

func (b *writeBuffer) Write(c byte) {
	b.Bytes[b.pos] = c
	b.pos++
}

func (b *writeBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (r *socketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofSocketRequest)}
	b.Write(r.family)
	b.Write(r.protocol)
	b.Write(r.ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.states)
	networkOrder.PutUint16(b.Next(2), r.id.sourcePort)
	networkOrder.PutUint16(b.Next(2), r.id.destinationPort)
	if r.family == unix.AF_INET6 {
		copy(b.Next(16), r.id.source)
		copy(b.Next(16), r.id.destination)
	} else {
		copy(b.Next(4), r.id.source.To4())
		b.Next(12)
		copy(b.Next(4), r.id.destination.To4())
		b.Next(12)
	}
	native.PutUint32(b.Next(4), r.id._interface)
	native.PutUint32(b.Next(4), r.id.cookie[0])
	native.PutUint32(b.Next(4), r.id.cookie[1])
	return b.Bytes
}

func (r *socketRequest) Len() int { return sizeofSocketRequest }

type readBuffer struct {
	Bytes []byte
	pos   int
}

func (b *readBuffer) Read() byte {
	c := b.Bytes[b.pos]
	b.pos++
	return c
}

func (b *readBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (s *_socket) deserialize(b []byte) error {
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	rb := readBuffer{Bytes: b}
	s.family = rb.Read()
	s.state = rb.Read()
	s.timer = rb.Read()
	s.retrans = rb.Read()
	s.id.sourcePort = networkOrder.Uint16(rb.Next(2))
	s.id.destinationPort = networkOrder.Uint16(rb.Next(2))
	if s.family == unix.AF_INET6 {
		s.id.source = net.IP(rb.Next(16))
		s.id.destination = net.IP(rb.Next(16))
	} else {
		s.id.source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
		s.id.destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
	}
	s.id._interface = native.Uint32(rb.Next(4))
	s.id.cookie[0] = native.Uint32(rb.Next(4))
	s.id.cookie[1] = native.Uint32(rb.Next(4))
	s.expires = native.Uint32(rb.Next(4))
	s.rQueue = native.Uint32(rb.Next(4))
	s.wQueue = native.Uint32(rb.Next(4))
	s.uid = native.Uint32(rb.Next(4))
	s.inode = native.Uint32(rb.Next(4))
	return nil
}

func parseNetlink(family, protocol uint8) (sockets []Socket, err error) {
	var s *nl.NetlinkSocket
	s, err = nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return
	}
	defer s.Close()
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	var state uint32
	if protocol == unix.IPPROTO_UDP {
		state = 7
	} else if protocol == unix.IPPROTO_TCP {
		state = 10
	} else {
		err = fmt.Errorf("unsupported protocol %d", protocol)
		return
	}
	req.AddData(&socketRequest{
		family:   family,
		protocol: protocol,
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
				continue
			}
			sockInfo := &_socket{}
			if err := sockInfo.deserialize(m.Data); err != nil {
				continue
			}
			socket := Socket{
				SIP:       sockInfo.id.source,
				DIP:       sockInfo.id.destination,
				SPort:     sockInfo.id.sourcePort,
				DPort:     sockInfo.id.destinationPort,
				UID:       sockInfo.uid,
				Interface: sockInfo.id._interface,
				Family:    sockInfo.family,
				State:     sockInfo.state,
				Inode:     sockInfo.inode,
				Type:      protocol,
			}
			if user, err := user.LookupId(strconv.Itoa(int(sockInfo.uid))); err == nil {
				socket.Username = user.Name
			}
			sockets = append(sockets, socket)
		}
	}
	return
}
func netlinkGetSocket(disableProc bool) (sockets []Socket, err error) {
	var udpSockets, udp6Sockets, tcpSockets, tcp6Sockets []Socket
	udpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_UDP)
	if err != nil {
		return
	}
	sockets = append(sockets, udpSockets...)
	udp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_UDP)
	if err == nil {
		sockets = append(sockets, udp6Sockets...)
	}
	tcpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_TCP)
	if err == nil {
		sockets = append(sockets, tcpSockets...)
	}
	tcp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_TCP)
	if err == nil {
		sockets = append(sockets, tcp6Sockets...)
	}
	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	if !disableProc {
		procs, err := procfs.AllProcs()
		if err == nil {
			for _, p := range procs {
				fds, _ := p.FileDescriptorTargets()
				for _, fd := range fds {
					if strings.HasPrefix(fd, "socket:[") {
						inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
						index, ok := inodeMap[uint32(inode)]
						if ok {
							sockets[index].PID = int32(p.PID)
							sockets[index].Comm, _ = p.Comm()
							argv, err := p.CmdLine()
							if err == nil {
								if len(argv) > 16 {
									argv = argv[:16]
								}
								sockets[index].Argv = strings.Join(argv, " ")
								if len(sockets[index].Argv) > 32 {
									sockets[index].Argv = sockets[index].Argv[:32]
								}
							}
						}
					}
				}
			}
		}
	}
	return
}
