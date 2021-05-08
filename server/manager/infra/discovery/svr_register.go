package discovery

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/levigross/grequests"
	"math/rand"
	"time"
)

const (
	sdRegisterURL           = "http://%s/registry/register"
	sdEvictURL              = "http://%s/registry/evict"
	defaultRegisterInterval = 30
)

type ServerRegistry struct {
	Name     string `json:"name"`
	Ip       string `json:"ip"`
	Port     int    `json:"port"`
	Weight   int    `json:"weight"`
	SDHost   string
	stopChan chan struct{}
}

func NewServerRegistry() *ServerRegistry {
	host := infra.SDAddrs[rand.Int()%len(infra.SDAddrs)]
	return NewRegistry(infra.RegisterName, infra.LocalIP, host, infra.HttpPort)
}

func NewRegistry(svrName, ip, sdUrl string, port int) *ServerRegistry {
	svr := &ServerRegistry{
		Name:     svrName,
		Ip:       ip,
		Port:     port,
		Weight:   0,
		SDHost:   sdUrl,
		stopChan: make(chan struct{}),
	}

	fmt.Printf(">>>>new registry: %#v\n", *svr)
	option := midware.SdAuthRequestOption()
	option.JSON = map[string]interface{}{
		"name":   svr.Name,
		"ip":     svr.Ip,
		"port":   svr.Port,
		"weight": svr.Weight,
	}
	option.RequestTimeout = 2 * time.Second
	url := fmt.Sprintf(sdRegisterURL, sdUrl)
	r, err := grequests.Post(url, option)
	if err != nil {
		ylog.Errorf("NewRegistry", "register failed: %v", err)
		fmt.Printf("register error: %s\n", err.Error())
		return svr
	}
	fmt.Printf(">>>>register response: %s\n", r.String())
	//fmt.Printf("register response: %s\n", r.String())
	go svr.renewRegistry()
	return svr
}

func (s *ServerRegistry) renewRegistry() {
	t := time.NewTicker(defaultRegisterInterval * time.Second)
	url := fmt.Sprintf(sdRegisterURL, s.SDHost)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			option := midware.SdAuthRequestOption()
			option.JSON = map[string]interface{}{
				"name":   s.Name,
				"ip":     s.Ip,
				"port":   s.Port,
				"weight": s.Weight,
			}
			option.RequestTimeout = 2 * time.Second
			ylog.Infof("RenewRegistry", ">>>>register %s %s %d %d to SD %s", s.Name, s.Ip, s.Port, s.Weight, url)
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

	option := midware.SdAuthRequestOption()
	option.JSON = map[string]interface{}{
		"name": s.Name,
		"ip":   s.Ip,
		"port": s.Port,
	}
	option.RequestTimeout = 2 * time.Second
	url := fmt.Sprintf(sdEvictURL, s.SDHost)
	if resp, err = grequests.Post(url, option); err != nil {
		ylog.Errorf("ServerRegistryStop", "####evict server failed: %v", err)
		return
	}
	ylog.Debugf("ServerRegistryStop", ">>>>evict server resp: %s", resp.String())
}

func (s *ServerRegistry) SetWeight(w int) {
	s.Weight = w
}
