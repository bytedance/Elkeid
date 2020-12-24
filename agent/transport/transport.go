package transport

import (
	"sync"

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
