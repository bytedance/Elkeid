package discovery

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/manger/infra"
	"github.com/levigross/grequests"
	"math/rand"
	"time"
)

const (
	registryURL = "http://%s/registry/detail?name=%s"
)

type registry struct {
	Name     string                 `json:"name"`   //server name
	Ip       string                 `json:"ip"`     //server ip
	Port     int                    `json:"port"`   //server port
	Status   int                    `json:"status"` //server status
	CreateAt int64                  `json:"create_at"`
	UpdateAt int64                  `json:"update_at"`
	Weight   int                    `json:"weight"` //server weight(负载权重，负载均衡使用)
	Extra    map[string]interface{} `json:"extra"`  //其他数据
}

type rspInfo struct {
	Msg  string     `json:"msg"`
	Data []registry `json:"data"`
}

func FetchRegistry(name string) ([]string, error) {
	var (
		hosts []string
	)
	sdHost := infra.SDAddrs[rand.Int()%len(infra.SDAddrs)]
	url := fmt.Sprintf(registryURL, sdHost, name)
	//fmt.Printf("fetch registry: %s\n", url)
	//request ds
	rsp, err := grequests.Get(url, &grequests.RequestOptions{
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		return hosts, err
	}
	r := &rspInfo{
		Data: make([]registry, 0),
	}
	if err = json.Unmarshal(rsp.Bytes(), r); err != nil {
		return hosts, err
	}
	for _, item := range r.Data {
		hosts = append(hosts, fmt.Sprintf("%s:%d", item.Ip, item.Port))
	}
	return hosts, nil
}

func GetHosts() []string {
	hosts, _ := FetchRegistry(infra.RegisterName)
	return hosts
}

func GetOtherHosts() []string {
	othHosts := make([]string, 0)
	hosts, err := FetchRegistry(infra.RegisterName)
	if err != nil {
		return othHosts
	}
	for _, item := range hosts {
		if item == fmt.Sprintf("%s:%d", infra.LocalIP, infra.HttpPort) {
			continue
		}
		othHosts = append(othHosts, item)
	}
	//fmt.Printf("other hosts: %v\n", othHosts)
	return othHosts
}
