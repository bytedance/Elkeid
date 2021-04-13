package endpoint

import (
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/cluster"
	"github.com/bytedance/Elkeid/server/service_discovery/common/safemap"
	"github.com/bytedance/Elkeid/server/service_discovery/common/ylog"
	"github.com/bytedance/Elkeid/server/service_discovery/server/midware"
	"github.com/levigross/grequests"
	"sync"
	"time"
)

const (
	defaultMergeNum       = 100
	defaultSendInterval   = 2
	defaultSendChannelLen = 1024 * 8
	defaultRecvChannelLen = 1024 * 8

	defaultRegistryRefreshInterval = 15

	syncUrl            = "http://%s/registry/sync"
	defaultSyncTimeout = 2

	registerAction = "REGISTER"
	evictAction    = "EVICT"
)

const (
	StatusGreen = iota
	StatusBlue
	StatusYellow
	StatusOrange
	StatusRed
)

type Registry struct {
	Name     string                 `json:"name"`   //server name
	Ip       string                 `json:"ip"`     //server ip
	Port     int                    `json:"port"`   //server port
	Status   int                    `json:"status"` //server status
	CreateAt int64                  `json:"create_at"`
	UpdateAt int64                  `json:"update_at"`
	Weight   int                    `json:"weight"` //server weight(负载权重，负载均衡使用)
	Extra    map[string]interface{} `json:"extra"`  //其他数据
}

type SyncInfo struct {
	Action   string   `json:"action"`
	Registry Registry `json:"registry"`
}

type TransInfo struct {
	Source string     `json:"source"`
	Data   []SyncInfo `json:"data"`
}

type Endpoint struct {
	cluster     cluster.Cluster
	registryMap *safemap.SafeMap
	sendChan    chan SyncInfo
	recvChan    chan TransInfo
	stop        chan bool
}

func NewEndpoint(cluster cluster.Cluster) *Endpoint {
	e := &Endpoint{
		cluster:     cluster,
		registryMap: safemap.NewSafeMap("registry"),
		sendChan:    make(chan SyncInfo, defaultSendChannelLen),
		recvChan:    make(chan TransInfo, defaultRecvChannelLen),
		stop:        make(chan bool),
	}

	go e.registryRefresh()
	go e.syncSend()
	go e.syncRecv()

	return e
}

func (e *Endpoint) Stop() {
	close(e.stop)
}

func (e *Endpoint) registryRefresh() {
	t := time.NewTicker(defaultRegistryRefreshInterval * time.Second)
	defer t.Stop()
	for {
		nowAt := time.Now().Unix()
		select {
		case <-t.C:
			names := e.registryMap.Keys()
			for _, name := range names {
				regMap := e.registryMap.Get(name)
				if regMap == nil {

					continue
				}
				for _, r := range regMap {
					//90s无心跳
					reg := r.(Registry)
					d := nowAt - reg.UpdateAt
					if d <= 45 {
						reg.Status = StatusGreen
						e.registryMap.HSet(name, fmt.Sprintf("%s:%d", reg.Ip, reg.Port), reg)
					} else if d > 45 && d <= 60 {
						reg.Status = StatusBlue
						e.registryMap.HSet(name, fmt.Sprintf("%s:%d", reg.Ip, reg.Port), reg)
					} else if d > 60 && d <= 75 {
						reg.Status = StatusYellow
						e.registryMap.HSet(name, fmt.Sprintf("%s:%d", reg.Ip, reg.Port), reg)
					} else if d > 75 && d <= 90 {
						reg.Status = StatusOrange
						e.registryMap.HSet(name, fmt.Sprintf("%s:%d", reg.Ip, reg.Port), reg)
					} else if d > 90 && d <= 105 {
						reg.Status = StatusRed
						e.registryMap.HSet(name, fmt.Sprintf("%s:%d", reg.Ip, reg.Port), reg)
					} else {
						ylog.Debugf("registryRefresh", "evict registry: %s, %s, %d", name, reg.Ip, reg.Port)
						e.Evict(name, reg.Ip, reg.Port)
					}
				}
			}
		case <-e.stop:
			return
		}
	}
}

func send(wg *sync.WaitGroup, host string, data *TransInfo) {
	//fmt.Printf("send data: %v\n", data)
	defer wg.Done()
	url := fmt.Sprintf(syncUrl, host)
	option := midware.AuthRequestOption()
	option.JSON = data
	option.RequestTimeout = defaultSyncTimeout * time.Second
	_, err := grequests.Post(url, option)
	if err != nil {
		ylog.Errorf("send_error", "sync send data to %s error: %s\n", host, err.Error())
		return
	}
	return
}

//sync send data
func (e *Endpoint) syncSend() {
	t := time.NewTicker(defaultSendInterval * time.Second)
	defer t.Stop()
	syncInfoList := make([]SyncInfo, 0)
	for {
		select {
		case syncInfo := <-e.sendChan:
			//fmt.Printf("sync info: %v\n", syncInfo)
			syncInfoList = append(syncInfoList, syncInfo)
			if len(syncInfoList) >= defaultMergeNum {
				//send to other endpoint
				hosts := e.cluster.GetOtherHosts()
				transInfo := &TransInfo{
					Source: e.cluster.GetHost(),
					Data:   syncInfoList,
				}
				wg := &sync.WaitGroup{}
				wg.Add(len(hosts))
				for _, host := range hosts {
					go send(wg, host, transInfo)
				}
				wg.Wait()
				syncInfoList = make([]SyncInfo, 0)
			}
		case <-t.C:
			if len(syncInfoList) > 0 {
				//send to other endpoint
				hosts := e.cluster.GetOtherHosts()
				transInfo := &TransInfo{
					Source: e.cluster.GetHost(),
					Data:   syncInfoList,
				}
				wg := &sync.WaitGroup{}
				wg.Add(len(hosts))
				for _, host := range hosts {
					go send(wg, host, transInfo)
				}
				wg.Wait()
				syncInfoList = make([]SyncInfo, 0)
			}
		case <-e.stop:
			ylog.Debugf("syncSend", "syncSend run stop")
			return
		}
	}
}

func (e *Endpoint) Recv(transInfo TransInfo) error {
	select {
	case e.recvChan <- transInfo:
	default:
		ylog.Debugf("recv", "recv channel is block")
		return errors.New("recv channel is block")
	}
	return nil
}

//sync recv data
func (e *Endpoint) syncRecv() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case transInfo := <-e.recvChan:
			//fmt.Printf("recv data: %v\n", transInfo)
			for _, syncInfo := range transInfo.Data {
				switch syncInfo.Action {
				case registerAction:
					e.registryMap.HSet(syncInfo.Registry.Name, fmt.Sprintf("%s:%d", syncInfo.Registry.Ip, syncInfo.Registry.Port), syncInfo.Registry)
				case evictAction:
					e.registryMap.HDel(syncInfo.Registry.Name, fmt.Sprintf("%s:%d", syncInfo.Registry.Ip, syncInfo.Registry.Port))
				}
			}
		case <-t.C:
		case <-e.stop:
			ylog.Debugf("syncRecv", "syncRecv run stop")
			return
		}
	}
}

//register action
func (e *Endpoint) Register(name string, ip string, port int, weight int, extra map[string]interface{}) {
	var (
		reg Registry
	)
	ts := time.Now().Unix()
	r := e.registryMap.HGet(name, fmt.Sprintf("%s:%d", ip, port))
	if r == nil {
		reg = Registry{
			Name:     name,
			Ip:       ip,
			Port:     port,
			Status:   StatusGreen,
			CreateAt: ts,
			UpdateAt: ts,
			Weight:   weight,
			Extra:    extra,
		}
		e.registryMap.HSet(name, fmt.Sprintf("%s:%d", ip, port), reg)
	} else {
		reg = r.(Registry)
		reg.Weight = weight
		reg.UpdateAt = ts
		e.registryMap.HSet(name, fmt.Sprintf("%s:%d", ip, port), reg)
	}

	syncInfo := SyncInfo{
		Action:   registerAction,
		Registry: reg,
	}
	//sync to other endpoint
	select {
	case e.sendChan <- syncInfo:
	default:
		ylog.Debugf("Register", "send channel is block")
	}
}

//evict action
func (e *Endpoint) Evict(name string, ip string, port int) {
	//delete from local memory
	e.registryMap.HDel(name, fmt.Sprintf("%s:%d", ip, port))
	//
	syncInfo := SyncInfo{
		Action: evictAction,
		Registry: Registry{
			Name: name,
			Ip:   ip,
			Port: port,
		},
	}
	//sync to other endpoint
	select {
	case e.sendChan <- syncInfo:
	default:
		ylog.Debugf("Evict", "send channel is block\n")
	}
}

//fetch registry
func (e *Endpoint) Fetch(name string, n int, fa FetchAlgorithm) ([]Registry, error) {
	var (
		regs []Registry
	)
	regMap := e.registryMap.Get(name)
	if regMap == nil {
		return regs, errors.New(fmt.Sprintf("server %s no instance", name))
	}

	items := make(ItemList, 0)
	for _, reg := range regMap {
		i := Item{
			Data:  reg.(Registry),
			Score: reg.(Registry).Weight,
		}
		items = append(items, i)
	}

	r := fa(items, n)
	for _, i := range r {
		reg := i.Data.(Registry)
		regs = append(regs, reg)
	}

	return regs, nil
}

//registry summary
func (e *Endpoint) RegistrySummary() map[string]int {
	suMap := make(map[string]int)
	names := e.registryMap.Keys()
	for _, name := range names {
		suMap[name] = e.registryMap.HLen(name)
	}
	return suMap
}

//registry name list
func (e *Endpoint) RegistryList() []string {
	return e.registryMap.Keys()
}

//registry detail
func (e *Endpoint) RegistryDetail(name string) []Registry {
	regs := make([]Registry, 0)
	regMap := e.registryMap.Get(name)
	for _, reg := range regMap {
		regs = append(regs, reg.(Registry))
	}
	return regs
}
