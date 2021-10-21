package socket

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

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
		return nil, fmt.Errorf("Unable to parse IP %s", hexIP)
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
			fmt.Println(header)
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

func netstatGetSocket(disableProc bool) (sockets []Socket, err error) {
	tcpSocks, err := parseProcNet(unix.AF_INET, unix.IPPROTO_TCP, "/proc/net/tcp")
	if err == nil {
		sockets = append(sockets, tcpSocks...)
	}
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
