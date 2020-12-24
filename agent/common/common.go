package common

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	PrivateIPv4   []string
	PublicIPv4    []string
	PrivateIPv6   []string
	PublicIPv6    []string
	AgentID       string
	Hostname      string
	Distro        string
	KernelVersion string
)

const (
	Version = "0.0.0.1"
)

var IDPath = "agent-id"

func init() {
	id, err := ioutil.ReadFile(IDPath)
	if err != nil {
		AgentID = uuid.New().String()
		err = ioutil.WriteFile(IDPath, []byte(AgentID), 0700)
		if err != nil {
			AgentID = "PLACEHOLDER-WRITE-AGENT-ID-ERROR-" + err.Error()
			fmt.Fprintf(os.Stderr, "Failed to write agent id file:%v", err)
		}
	} else {
		_, err = uuid.Parse(string(id))
		if err != nil {
			AgentID = uuid.New().String()
			err = ioutil.WriteFile(IDPath, []byte(AgentID), 0700)
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
		if strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "lo") || strings.HasPrefix(i.Name, "br-") {
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
	Hostname, err = os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't get hostname:%v", err)
		Hostname = "PLACEHOLDER-GET-HOSTNAME-ERROR-" + err.Error()
	}
	kcontent, err := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't get kernel version:%v", err)
		KernelVersion = "PLACEHOLDER-GET-KVERSION-ERROR-" + err.Error()
	} else {
		KernelVersion = strings.TrimSpace(string(kcontent))
	}
	files, err := ioutil.ReadDir("/etc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't get distribution version:%v", err)
		Distro = "PLACEHOLDER-GET-DISTRIBUTION-ERROR-" + err.Error()
	} else {
		for _, i := range files {
			if strings.HasSuffix(i.Name(), "release") && i.Size() < 1024*1024 {
				content, err := ioutil.ReadFile("/etc/" + i.Name())
				if err != nil {
					continue
				}
				if strings.Contains(string(content), "Debian") {
					Distro = "debian"
				} else if strings.Contains(string(content), "CentOS") {
					Distro = "centos"
				} else {
					Distro = "else"
				}
			}
		}
	}
}
