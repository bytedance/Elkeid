package plugin

import (
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/agent/plugin/procotol"
	"github.com/bytedance/Elkeid/agent/transport"

	"github.com/tinylib/msgp/msgp"
	"go.uber.org/zap"
)

var SocketPath = "plugin.sock"

// Server is the unix doamin socket listener of the plugin, and it maintains a plugin map
type Server struct {
	m  map[string]*Plugin
	mu sync.Mutex
	l  net.Listener
}

// ForEach is used to traverse all plugin instances with specified operations,
// for efficiency reasons, do not perform longer operations
func (s *Server) ForEach(f func(string, *Plugin)) {
	s.mu.Lock()
	for k, p := range s.m {
		f(k, p)
	}
	s.mu.Unlock()
}

// PluginList func traverses the server map and returns all plugin names
func (s *Server) PluginList() []string {
	s.mu.Lock()
	l := []string{}
	for k := range s.m {
		l = append(l, k)
	}
	s.mu.Unlock()
	return l
}

// Insert a new plugin, note: if there is a plugin with the same name before, please close it first
func (s *Server) Insert(k string, p *Plugin) {
	s.mu.Lock()
	s.m[k] = p
	s.mu.Unlock()
}

// Get func gets the plugin instance with the corresponding name from the Server
func (s *Server) Get(k string) (*Plugin, bool) {
	s.mu.Lock()
	p, ok := s.m[k]
	s.mu.Unlock()
	return p, ok
}

// Delete func deletes a plugin instance from the server,
// the Close() method of the plugin will be called before deleting from the map
func (s *Server) Delete(k string) {
	p, ok := s.Get(k)
	if ok {
		p.Close(true)
		s.mu.Lock()
		delete(s.m, k)
		s.mu.Unlock()
	}
}

// Close func closes the unix domain socket listener in the server and deletes all plugin instances
func (s *Server) Close() {
	s.l.Close()
	time.Sleep(exitTimeout)
	s.mu.Lock()
	for _, v := range s.m {
		v.Close(false)
	}
	s.m = make(map[string]*Plugin, 10)
	s.mu.Unlock()
}

// Globally unique server instance
var instance *Server

// GetServer func is used to obtain the server instance, please note: this function is not concurrently safe
func GetServer() (*Server, error) {
	if instance == nil {
		err := os.RemoveAll("plugin.sock")
		if err != nil {
			return nil, err
		}
		l, err := net.Listen("unix", "plugin.sock")
		if err != nil {
			return nil, err
		}
		instance = &Server{l: l, m: make(map[string]*Plugin, 10)}
	}
	return instance, nil
}

// Run is used for plugin server.
func Run() {
	defer func() {
		if err := recover(); err != nil {
			time.Sleep(time.Second)
			panic(err)
		}
	}()
	s, err := GetServer()
	if err != nil {
		zap.S().Panic(err)
	}
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				zap.S().Panicf("Accept connect error: %v", err)
			}
			return
		}
		go func() {
			r := msgp.NewReader(conn)
			req := procotol.RegistRequest{}
			err := (&req).DecodeMsg(r)
			if err != nil {
				zap.S().Error(err)
				conn.Close()
				return
			}
			zap.S().Infof("Received a registration:%+v", req)
			p, ok := s.Get(req.Name)
			if !ok {
				zap.S().Errorf("Plugin %v isn't in map", req.Name)
				conn.Close()
				return
			}
			err = p.Connect(req, conn)
			if err != nil {
				zap.S().Error(err)
				if err.Error() != "The same plugin has been connected, it may be a malicious attack" {
					s.Delete(req.Name)
				}
				return
			}
			zap.S().Infof("Plugin has been successfully connected:%+v", p)
			go func() {
				for {
					data, err := p.Receive()
					if err != nil {
						if err != io.EOF {
							zap.S().Error(err)
						}
						s.Delete(req.Name)
						return
					}
					err = transport.Send(data)
					if err != nil {
						zap.S().Error(err)
					}
				}
			}()
		}()
	}
}
