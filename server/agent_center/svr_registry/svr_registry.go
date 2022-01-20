package svr_registry

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/grpc_handler"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/midware"
	"github.com/levigross/grequests"
	"math/rand"
	"time"
)

type ServerRegistry struct {
	Name   string                 `json:"name"`
	Ip     string                 `json:"ip"`
	Port   int                    `json:"port"`
	Weight int                    `json:"weight"`
	Extra  map[string]interface{} `json:"extra"`

	AddrList []string      `json:"-"`
	stopChan chan struct{} `json:"-"`
}

func init() {
	rand.Seed(time.Now().Unix())
}

func NewGRPCServerRegistry() *ServerRegistry {
	return NewRegistry(fmt.Sprintf(`%s_grpc`, common.SvrName), common.LocalIP, common.SdAddrs, common.GRPCPort)
}

func NewHttpServerRegistry() *ServerRegistry {
	return NewRegistry(fmt.Sprintf(`%s_http`, common.SvrName), common.LocalIP, common.SdAddrs, common.HttpPort)
}

func NewRegistry(svrName, ip string, addrList []string, port int) *ServerRegistry {
	svr := &ServerRegistry{
		Name:     svrName,
		Ip:       ip,
		Port:     port,
		Weight:   0,
		AddrList: addrList,
		stopChan: make(chan struct{}),
	}

	ylog.Infof("NewRegistry", ">>>>new registry: %s", *svr)
	option := midware.AuthRequestOption()
	option.JSON = svr
	resp, err := grequests.Post(fmt.Sprintf("http://%s/registry/register", svr.randomAddr()), option)
	if err != nil {
		fmt.Printf("[NewRegistry] >>>>new registry %s error, resp: %s\n", svr.print(), resp.String())
		ylog.Errorf("NewRegistry", "NewRegistry failed: %v", err)
		return svr
	}

	fmt.Printf("[NewRegistry] >>>>new registry %s resp: %s\n", svr.print(), resp.String())
	ylog.Infof("NewRegistry", ">>>>new registry %s resp: %s", svr.print(), resp.String())

	go svr.renewRegistry()
	return svr
}

func (s *ServerRegistry) renewRegistry() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			url := fmt.Sprintf("http://%s/registry/register", s.randomAddr())

			//Update the current number of connections
			s.Weight = grpc_handler.GlobalGRPCPool.GetCount()
			option := midware.AuthRequestOption()
			option.JSON = s
			ylog.Infof("RenewRegistry", ">>>>register %s to FindYou %s", s.print(), url)
			resp, err := grequests.Post(url, option)
			if err != nil {
				ylog.Errorf("RenewRegistry", "####renew registry failed: %v", err)
				continue
			}
			ylog.Debugf("RenewRegistry", ">>>>renew registry resp: %s", resp.String())
		case <-s.stopChan:
			return
		}
	}
}

func (s *ServerRegistry) Stop() {
	var (
		err  error
		resp *grequests.Response
	)
	//stop renew
	close(s.stopChan)

	option := midware.AuthRequestOption()
	option.JSON = s
	if resp, err = grequests.Post(fmt.Sprintf("http://%s/registry/evict", s.randomAddr()), option); err != nil {
		ylog.Errorf("ServerRegistryStop", "####evict server failed: %v", err)
		return
	}
	fmt.Printf("[ServerRegistry] >>>> %s server stopped, resp: %s\n", s.Name, resp.String())
	ylog.Debugf("ServerRegistryStop", ">>>>evict server resp: %s", resp.String())
}

func (s *ServerRegistry) SetWeight(w int) {
	s.Weight = w
}

func (s *ServerRegistry) randomAddr() string {
	return s.AddrList[rand.Intn(len(s.AddrList))]
}

func (s *ServerRegistry) print() string {
	tmp, _ := json.Marshal(s)
	return string(tmp)
}
