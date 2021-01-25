package transport

import (
	"sync"

	"github.com/bytedance/AgentSmith-HIDS/agent/common"
	"github.com/bytedance/AgentSmith-HIDS/agent/spec"
	"github.com/bytedance/AgentSmith-HIDS/agent/transport/stdout"
)

var (
	mu               sync.Mutex
	defaultTransport Transport
)

func init() { defaultTransport = &stdout.Stdout{} }

type Transport interface {
	Send(*spec.Data) error
	Receive() (spec.Task, error)
	Close()
}

func SetTransport(t Transport) {
	defaultTransport = t
}

func Send(d *spec.Data) error {
	mu.Lock()
	defer mu.Unlock()
	for i := range *d {
		(*d)[i]["agent_id"] = common.AgentID
		if len(common.PrivateIPv4) != 0 {
			(*d)[i]["ipv4"] = common.PrivateIPv4[0]
		} else if len(common.PublicIPv4) != 0 {
			(*d)[i]["ipv4"] = common.PublicIPv4[0]
		} else {
			(*d)[i]["ipv4"] = ""
		}
		if len(common.PrivateIPv6) != 0 {
			(*d)[i]["ipv6"] = common.PrivateIPv6[0]
		} else if len(common.PublicIPv6) != 0 {
			(*d)[i]["ipv6"] = common.PublicIPv6[0]
		} else {
			(*d)[i]["ipv6"] = ""
		}
		(*d)[i]["hostname"] = common.Hostname
		(*d)[i]["version"] = common.Version
		(*d)[i]["kernel_version"] = common.KernelVersion
		(*d)[i]["distro"] = common.Distro
	}
	return defaultTransport.Send(d)
}
func Receive() (spec.Task, error) {
	mu.Lock()
	defer mu.Unlock()
	return defaultTransport.Receive()
}
func Close() {
	mu.Lock()
	defer mu.Unlock()
	defaultTransport.Close()
}
