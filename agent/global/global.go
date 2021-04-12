package global

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/host"
)

var (
	PrivateIPv4     []string
	PublicIPv4      []string
	PrivateIPv6     []string
	PublicIPv6      []string
	AgentID         string
	Hostname        string
	Platform        string
	PlatformFamily  string
	PlatformVersion string
	KernelVersion   string
)

const (
	Version = "1.6.0.0"
)

// 全局Channel Others->gRPC
var (
	GrpcChannel chan []*Record
)

func init() {
	GrpcChannel = make(chan []*Record, 1000)
	id, err := ioutil.ReadFile("machine-id")
	if err != nil {
		AgentID = uuid.New().String()
		err = ioutil.WriteFile("machine-id", []byte(AgentID), 0700)
		if err != nil {
			AgentID = "PLACEHOLDER-WRITE-AGENT-ID-ERROR-" + err.Error()
			fmt.Fprintf(os.Stderr, "Failed to write agent id file:%v", err)
		}
	} else {
		_, err = uuid.Parse(string(id))
		if err != nil {
			AgentID = uuid.New().String()
			err = ioutil.WriteFile("machine-id", []byte(AgentID), 0700)
			if err != nil {
				AgentID = "PLACEHOLDER-WRITE-AGENT-ID-ERROR-" + err.Error()
				fmt.Fprintf(os.Stderr, "Failed to write agent id file:%v", err)
			}
		} else {
			AgentID = string(id)
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't get interfaces:%v", err)
	}
	for _, i := range interfaces {
		if strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "lo") {
			continue
		}
		addr, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, j := range addr {
			ip, _, err := net.ParseCIDR(j.String())
			if err != nil {
				continue
			}
			if ip.To4() == nil {
				if strings.HasPrefix(ip.String(), "fe80") {
					continue
				}
				if strings.HasPrefix(ip.String(), "fd") {
					PrivateIPv6 = append(PrivateIPv6, ip.String())
				} else {
					PublicIPv6 = append(PublicIPv6, ip.String())
				}
			} else {
				if strings.HasPrefix(ip.String(), "169.254.") {
					continue
				}
				if strings.HasPrefix(ip.String(), "10.") || strings.HasPrefix(ip.String(), "192.168.") || regexp.MustCompile(`^172\.([1][6-9]|[2]\d|[3][0-1])\.`).MatchString(ip.String()) {
					PrivateIPv4 = append(PrivateIPv4, ip.String())
				} else {
					PublicIPv4 = append(PublicIPv4, ip.String())
				}

			}
		}
	}
	Platform, PlatformFamily, PlatformVersion, _ = host.PlatformInformation()
	KernelVersion, _ = host.KernelVersion()
	Hostname, _ = os.Hostname()
}
