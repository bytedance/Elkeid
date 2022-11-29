package port

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bytedance/Elkeid/plugins/collector/utils"
	"golang.org/x/sys/unix"
)

func parseIP(h string) (ret string, err error) {
	var byteIP []byte
	byteIP, err = hex.DecodeString(h)
	if err != nil {
		return
	}
	switch len(byteIP) {
	case 4:
		ret = net.IP{byteIP[3], byteIP[2], byteIP[1], byteIP[0]}.String()
		return
	case 16:
		ret = net.IP{
			byteIP[3], byteIP[2], byteIP[1], byteIP[0],
			byteIP[7], byteIP[6], byteIP[5], byteIP[4],
			byteIP[11], byteIP[10], byteIP[9], byteIP[8],
			byteIP[15], byteIP[14], byteIP[13], byteIP[12],
		}.String()
		return
	default:
		err = fmt.Errorf("unable to parse IP %s", h)
		return
	}
}

func procNet(family, proto uint8) (ret []*Port, err error) {
	var f *os.File
	var f1, f2 string
	if proto == unix.IPPROTO_UDP {
		f1 = "udp"
	} else if proto == unix.IPPROTO_TCP {
		f1 = "tcp"
	} else {
		err = fmt.Errorf("unsupported protocol %d", proto)
		return
	}
	if family == unix.AF_INET {
		f2 = "4"
	} else if family == unix.AF_INET6 {
		f2 = "6"
	} else {
		err = fmt.Errorf("unsupported family %d", family)
		return
	}
	if err != nil {
		return
	}
	f, err = os.Open(filepath.Join("/proc/net", f1+f2))
	if err != nil {
		return
	}
	sf := strconv.Itoa(int(family))
	sp := strconv.Itoa(int(proto))
	r := bufio.NewScanner(io.LimitReader(f, 1024*1024*2))
	hdr := map[int]string{}
	for i := 0; r.Scan(); i++ {
		if i == 0 {
			hdr[1] = "local_address"
			hdr[2] = "rem_address"
			hdr[3] = "st"
			hdr[7] = "uid"
			for index, field := range strings.Fields(r.Text()[strings.Index(r.Text(), "uid")+3:]) {
				hdr[8+index] = field
			}

		} else {
			fields := strings.Fields(r.Text())
			p := &Port{}
			var err error
			for i, f := range fields {
				if k, ok := hdr[i]; ok {
					switch k {
					case "local_address":
						fields := strings.Split(f, ":")
						if len(fields) != 2 {
							break
						}
						p.Sip, err = parseIP(fields[0])
						if err != nil {
							break
						}
						var uport uint64
						uport, err = strconv.ParseUint(fields[1], 16, 64)
						if err != nil {
							break
						}
						p.Sport = strconv.FormatUint(uport, 10)
					case "rem_address":
						fields := strings.Split(f, ":")
						if len(fields) != 2 {
							break
						}
						p.Dip, err = parseIP(fields[0])
						if err != nil {
							break
						}
						var uport uint64
						uport, err = strconv.ParseUint(fields[1], 16, 64)
						if err != nil {
							break
						}
						p.Dport = strconv.FormatUint(uport, 10)
					case "st":
						var st uint64
						st, err = strconv.ParseUint(f, 16, 64)
						if err != nil {
							break
						}
						p.State = strconv.FormatUint(st, 10)
					case "uid":
						p.Uid = f
						p.Username, _ = utils.GetUsername(f)
					case "inode":
						p.Inode = f
					}
				}
			}
			if err == nil && ((proto == unix.IPPROTO_UDP && p.State == "7") || (proto == unix.IPPROTO_TCP && p.State == "10")) {
				p.Protocol = sp
				p.Family = sf
				ret = append(ret, p)
			}
		}
	}
	return
}
