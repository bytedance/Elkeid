package monitor

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor/config"
	"strconv"
	"strings"
	"sync"
)

type ServiceInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var (
	ServiceHub = ServiceInfo{
		ID:          "Elkeid-Service-01",
		Name:        "HUB",
		Description: "Elkeid High Performance Data Processing Engine",
	}
	ServiceLeader = ServiceInfo{
		ID:          "Elkeid-Service-02",
		Name:        "Leader",
		Description: "Elkeid Hub Control Pane",
	}
	ServiceManager = ServiceInfo{
		ID:          "Elkeid-Service-03",
		Name:        "Manager",
		Description: "Elkeid Manager for agent and service",
	}
	ServiceAC = ServiceInfo{
		ID:          "Elkeid-Service-04",
		Name:        "Access",
		Description: "this is access",
	}
	ServiceSD = ServiceInfo{
		ID:          "Elkeid-Service-05",
		Name:        "ServiceDiscovery",
		Description: "this is service discovery",
	}
	ServiceMongodb = ServiceInfo{
		ID:          "Elkeid-Service-11",
		Name:        "MongoDB",
		Description: "this is mongodb",
	}
	ServiceKafka = ServiceInfo{
		ID:          "Elkeid-Service-12",
		Name:        "Kafka",
		Description: "this is kafka",
	}
	ServiceRedis = ServiceInfo{
		ID:          "Elkeid-Service-13",
		Name:        "Redis",
		Description: "this is redis",
	}
	ServiceES = ServiceInfo{
		ID:          "Elkeid-Service-14",
		Name:        "ElasticSearch",
		Description: "this is elastic search",
	}
)

type HostInfo struct {
	ID       string
	IP       string
	Services []string
}

func ipToID(ip string) string {
	// ipv6
	if strings.Contains(ip, ":") {
		return ip
	}

	// invalid ipv4
	if len(strings.Split(ip, ".")) != 4 {
		return ip
	}

	builder := strings.Builder{}
	builder.WriteString("n4-")
	for i, v := range strings.Split(ip, ".") {
		n, _ := strconv.Atoi(v)
		if i != 0 {
			builder.WriteString("-")
		}
		builder.WriteString(fmt.Sprintf("%.3d", n))
	}
	return builder.String()
}

var (
	allHostMap          map[string]*HostInfo
	allHostInfo         []HostInfo
	allHostInfoCalcOnce sync.Once
	serviceHostMap      map[string][]*HostInfo
)

func addHostByService(host config.Host, service string) {
	id := ipToID(host.Host)
	if info, ok := allHostMap[id]; ok {
		serviceExists := false
		for _, s := range info.Services {
			if s == service {
				serviceExists = true
			}
		}
		if !serviceExists {
			info.Services = append(info.Services, service)
		}
	} else {
		info = &HostInfo{
			ID:       ipToID(host.Host),
			IP:       host.Host,
			Services: []string{service},
		}
		allHostMap[id] = info
	}
}

func addHostsByService(hosts []config.Host, service string) {
	for _, host := range hosts {
		addHostByService(host, service)
	}
}

func GetAllHosts() []HostInfo {
	allHostInfoCalcOnce.Do(func() {
		allHostMap = make(map[string]*HostInfo)
		serviceHostMap = make(map[string][]*HostInfo)
		// hub
		addHostByService(Config.HUB.SSHHost, ServiceHub.Name)
		addHostByService(Config.HubLeader.SSHHost, ServiceLeader.Name)
		// other
		addHostsByService(Config.MG.SSHHost, ServiceManager.Name)
		addHostsByService(Config.AC.SSHHost, ServiceAC.Name)
		addHostsByService(Config.SD.SSHHost, ServiceSD.Name)
		addHostsByService(Config.Mongodb.SSHHost, ServiceMongodb.Name)
		addHostsByService(Config.Kafka.SSHHost, ServiceKafka.Name)
		addHostsByService(Config.Redis.SSHHost, ServiceRedis.Name)
		for _, host := range allHostMap {
			allHostInfo = append(allHostInfo, *host)
			for _, s := range host.Services {
				if _, ok := serviceHostMap[s]; ok {
					serviceHostMap[s] = append(serviceHostMap[s], host)
				} else {
					serviceHostMap[s] = []*HostInfo{host}
				}
			}
		}
	})
	return allHostInfo
}

func GetHostsByService(name string) []*HostInfo {
	_ = GetAllHosts()
	return serviceHostMap[name]
}

func GetServiceAllAddress(service string) []string {
	switch service {
	case ServiceHub.Name:
		return GetAllHubAddress()
	case ServiceLeader.Name:
		return GetAllLeaderAddress()
	case ServiceManager.Name:
		return GetAllManagerAddress()
	}
	return nil
}

func GetFirstHubAddress() string {
	return fmt.Sprintf("https://%s:8091", Config.HUB.SSHHost.Host)
}

func GetAllHubAddress() []string {
	return []string{GetFirstHubAddress()}
}

func GetFirstLeaderAddress() string {
	return fmt.Sprintf("http://%s:12310", Config.HubLeader.SSHHost.Host)
}

func GetAllLeaderAddress() []string {
	return []string{GetFirstLeaderAddress()}
}

func GetAllManagerAddress() []string {
	ret := make([]string, 0)
	for _, host := range Config.MG.SSHHost {
		ret = append(ret, fmt.Sprintf("http://%s:6701", host.Host))
	}
	return ret
}
