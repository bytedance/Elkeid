package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bytedance/plugins"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
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

const (
	INET_DIAG_NONE = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN
	INET_DIAG_DCTCPINFO
	INET_DIAG_PROTOCOL
	INET_DIAG_SKV6ONLY
	INET_DIAG_LOCALS
	INET_DIAG_PEERS
	INET_DIAG_PAD
	INET_DIAG_MARK
	INET_DIAG_BBRINFO
	INET_DIAG_CLASS_ID
	INET_DIAG_MD5SIG
	INET_DIAG_MAX
)

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
		ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
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
			socket.Username = GetUsername(int(socket.UID))
			sockets = append(sockets, socket)
		}
	}
	return
}

type Socket struct {
	DPort     uint16 `json:"dport"`
	SPort     uint16 `json:"sport"`
	DIP       net.IP `json:"dip"`
	SIP       net.IP `json:"sip"`
	Interface uint32 `json:"interface"`
	Family    uint8  `json:"family"`
	State     uint8  `json:"state"`
	UID       uint32 `json:"uid"`
	Username  string `json:"username"`
	Inode     uint32 `json:"inode"`
	PID       int    `json:"pid"`
	Cmdline   string `json:"argv"`
	Comm      string `json:"comm"`
	Type      uint8  `json:"type"`
}

func fromNetlink() (sockets []Socket, err error) {
	var udpSockets, udp6Sockets, tcpSockets, tcp6Sockets []Socket
	udpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_UDP)
	if err != nil {
		return
	}
	sockets = append(sockets, udpSockets...)
	udp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_UDP)
	if err != nil {
		return
	}
	sockets = append(sockets, udp6Sockets...)
	tcpSockets, err = parseNetlink(unix.AF_INET, unix.IPPROTO_TCP)
	if err != nil {
		return
	}
	sockets = append(sockets, tcpSockets...)
	tcp6Sockets, err = parseNetlink(unix.AF_INET6, unix.IPPROTO_TCP)
	if err == nil {
		return
	}
	sockets = append(sockets, tcp6Sockets...)
	return
}
func parseIP(hexIP string) (net.IP, error) {
	var byteIP []byte
	byteIP, err := hex.DecodeString(hexIP)
	if err != nil {
		return nil, fmt.Errorf("cannot parse address field in socket line %q", hexIP)
	}
	switch len(byteIP) {
	case 4:
		return net.IP{byteIP[3], byteIP[2], byteIP[1], byteIP[0]}, nil
	case 16:
		i := net.IP{
			byteIP[3], byteIP[2], byteIP[1], byteIP[0],
			byteIP[7], byteIP[6], byteIP[5], byteIP[4],
			byteIP[11], byteIP[10], byteIP[9], byteIP[8],
			byteIP[15], byteIP[14], byteIP[13], byteIP[12],
		}
		return i, nil
	default:
		return nil, fmt.Errorf("unable to parse IP %s", hexIP)
	}
}

func parseProcNet(family, protocol uint8, path string) (sockets []Socket, err error) {
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024*2))
	header := make(map[int]string)
	for i := 0; r.Scan(); i++ {
		if i == 0 {
			header[0] = "sl"
			header[1] = "local_address"
			header[2] = "rem_address"
			header[3] = "st"
			header[4] = "queue"
			header[5] = "t"
			header[6] = "retrnsmt"
			header[7] = "uid"
			for index, field := range strings.Fields(r.Text()[strings.Index(r.Text(), "uid")+3:]) {
				header[8+index] = field
			}
		} else {
			socket := Socket{Family: family, Type: protocol}
			droped := false
			for index, key := range strings.Fields(r.Text()) {
				switch header[index] {
				case "local_address":
					fields := strings.Split(key, ":")
					if len(fields) != 2 {
						droped = true
						break
					}
					socket.SIP, err = parseIP(fields[0])
					if err != nil {
						droped = true
						break
					}
					var port uint64
					port, err = strconv.ParseUint(fields[1], 16, 64)
					if err != nil {
						droped = true
						break
					}
					socket.SPort = uint16(port)
				case "rem_address":
					fields := strings.Split(key, ":")
					if len(fields) != 2 {
						droped = true
						break
					}
					socket.DIP, err = parseIP(fields[0])
					if err != nil {
						droped = true
						break
					}
					var port uint64
					port, err = strconv.ParseUint(fields[1], 16, 64)
					if err != nil {
						droped = true
						break
					}
					socket.DPort = uint16(port)
				case "st":
					st, err := strconv.ParseUint(key, 16, 64)
					if err != nil {
						continue
					}
					if (protocol == unix.IPPROTO_UDP && st != 7) || (protocol == unix.IPPROTO_TCP && st != 10) {
						droped = true
						break
					}
					socket.State = uint8(st)
				case "uid":
					uid, err := strconv.ParseUint(key, 0, 64)
					if err != nil {
						continue
					}
					socket.UID = uint32(uid)
					if user, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
						socket.Username = user.Name
					}
				case "inode":
					inode, err := strconv.ParseUint(key, 0, 64)
					if err != nil {
						continue
					}
					socket.Inode = uint32(inode)
				default:
				}
			}
			if !droped && len(socket.DIP) != 0 && len(socket.SIP) != 0 && socket.State != 0 {
				sockets = append(sockets, socket)
			}
		}

	}
	return
}

func fromProc() (sockets []Socket, err error) {
	tcpSocks, err := parseProcNet(unix.AF_INET, unix.IPPROTO_TCP, "/proc/net/tcp")
	if err != nil {
		return
	}
	sockets = append(sockets, tcpSocks...)
	tcp6Socks, err := parseProcNet(unix.AF_INET6, unix.IPPROTO_TCP, "/proc/net/tcp6")
	if err == nil {
		sockets = append(sockets, tcp6Socks...)
	}
	udpSocks, err := parseProcNet(unix.AF_INET, unix.IPPROTO_UDP, "/proc/net/udp")
	if err == nil {
		sockets = append(sockets, udpSocks...)
	}
	udp6Socks, err := parseProcNet(unix.AF_INET6, unix.IPPROTO_UDP, "/proc/net/udp6")
	if err == nil {
		sockets = append(sockets, udp6Socks...)
	}
	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	return
}
func GetSocket() {
	zap.S().Info("scanning socket")
	rec := &plugins.Record{
		DataType:  5001,
		Timestamp: time.Now().Unix(),
	}
	var sockets []Socket
	sockets, err := fromNetlink()
	if err != nil {
		zap.S().Warn("get socket from netlink failed:", err)
		zap.S().Info("try getting socket from proc...")
		sockets, _ = fromProc()
	}
	inodeMap := make(map[uint32]int)
	for index, socket := range sockets {
		if socket.Inode != 0 {
			inodeMap[socket.Inode] = index
		}
	}
	pids, err := GetPids()
	if err == nil {
		for _, pid := range pids {
			fds, err := GetProcessOpenedFiles(pid)
			if err == nil {
				for _, fd := range fds {
					if strings.HasPrefix(fd, "socket:[") {
						inode, _ := strconv.ParseUint(strings.TrimRight(fd[8:], "]"), 10, 32)
						index, ok := inodeMap[uint32(inode)]
						if ok {
							sockets[index].PID = pid
							sockets[index].Comm, _, _, _, _, _, _, _ = GetProcessStat(pid)
							cmdline, err := GetProcessCmdline(pid)
							if err == nil {
								if len(cmdline) > MaxFieldLen {
									cmdline = cmdline[:MaxFieldLen]
								}
								sockets[index].Cmdline = cmdline
							}
						}
					}
				}
			}
			time.Sleep(time.Millisecond * time.Duration(ProcessScanIntervalMillSec))
		}
	}
	zap.S().Infof("scan socket done: %v\n", len(sockets))
	data, _ := json.Marshal(sockets)
	rec.Data = &plugins.Payload{
		Fields: map[string]string{"data": string(data)},
	}
	Client.SendRecord(rec)
}
func init() {
	go func() {
		rand.Seed(time.Now().UnixNano())
		time.Sleep(time.Second * time.Duration(rand.Intn(600)))
		GetSocket()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d * * * * ", rand.Intn(60)), GetSocket)
		// Scheduler.AddFunc("@every 3m", GetSocket)
		SchedulerMu.Unlock()
	}()
}
