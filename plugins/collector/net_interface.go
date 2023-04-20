package main

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	plugins "github.com/bytedance/plugins"
)

func joinAddrs(addrs []net.Addr, sep string) string {
	strs := []string{}
	for _, addr := range addrs {
		strs = append(strs, addr.String())
	}
	return strings.Join(strs, sep)
}

type NetInterfaceHandler struct{}

func (*NetInterfaceHandler) Name() string {
	return "net_interface"
}
func (*NetInterfaceHandler) DataType() int {
	return 5059
}
func (h *NetInterfaceHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	nfs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, nf := range nfs {
		if addrs, err := nf.Addrs(); err == nil {
			c.SendRecord(&plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: map[string]string{
						"name":          nf.Name,
						"hardware_addr": nf.HardwareAddr.String(),
						"addrs":         joinAddrs(addrs, ","),
						"index":         strconv.Itoa(nf.Index),
						"mtu":           strconv.Itoa(nf.MTU),
						"package_seq":   seq,
					},
				},
			})
		}
	}
}
