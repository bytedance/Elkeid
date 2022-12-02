package resource

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func init() {
	if s, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		hostSerial = string(bytes.TrimSpace(s))
	}
	if s, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		hostID = string(bytes.TrimSpace(s))
	}
	if s, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		hostModel = string(bytes.TrimSpace(s))
	}
	if s, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		hostVendor = string(bytes.TrimSpace(s))
	}
}
func GetDNS() string {
	var svrs []string
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if strings.HasPrefix(s.Text(), "nameserver") {
				svrs = append(svrs, strings.TrimSpace(strings.TrimPrefix(s.Text(), "nameserver")))
			}
		}
		f.Close()
	}
	return strings.Join(svrs, ",")
}
func GetGateway() string {
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) > 3 {
				if flags, err := strconv.ParseInt(fields[3], 16, 64); err == nil {
					if (flags&unix.RTF_UP == unix.RTF_UP) && (flags&unix.RTF_GATEWAY == unix.RTF_GATEWAY) {
						if ipa, err := hex.DecodeString(fields[2]); err == nil && len(ipa) == 4 {
							return net.IP{ipa[3], ipa[2], ipa[1], ipa[0]}.String()
						}
					}
				}
			}
		}
	}
	return ""
}
