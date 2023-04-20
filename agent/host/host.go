package host

import (
	"net"
	"os"
	"strings"
	"sync/atomic"
)

var (
	// string
	Name atomic.Value
	// []string{}
	PrivateIPv4 atomic.Value
	PublicIPv4  atomic.Value
	PrivateIPv6 atomic.Value
	PublicIPv6  atomic.Value
)

func RefreshHost() {
	hostname, _ := os.Hostname()
	Name.Store(hostname)
	privateIPv4 := []string{}
	privateIPv6 := []string{}
	publicIPv4 := []string{}
	publicIPv6 := []string{}
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "lo") {
				continue
			}
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil || !ip.IsGlobalUnicast() {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					if (ip4[0] == 10) || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 172 && ip4[1] > 15 && ip4[1] < 32) {
						privateIPv4 = append(privateIPv4, ip4.String())
					} else {
						publicIPv4 = append(publicIPv4, ip4.String())
					}
				} else if len(ip) == net.IPv6len {
					if ip[0] == 0xfd {
						privateIPv6 = append(privateIPv6, ip.String())
					} else {
						publicIPv6 = append(publicIPv6, ip.String())
					}
				}
			}
		}
	}
	if len(privateIPv4) > 5 {
		privateIPv4 = privateIPv4[:5]
	}
	if len(privateIPv6) > 5 {
		privateIPv6 = privateIPv6[:5]
	}
	PrivateIPv4.Store(privateIPv4)
	PublicIPv4.Store(publicIPv4)
	PrivateIPv6.Store(privateIPv6)
	PublicIPv6.Store(publicIPv6)
}
func init() {
	RefreshHost()
}
