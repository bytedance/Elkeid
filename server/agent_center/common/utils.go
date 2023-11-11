package common

import (
	"math/rand"
	"net"
	"os"
	"time"
)

func CheckIPFormat(ip string) bool {
	address := net.ParseIP(ip)
	if address == nil {
		return false
	} else {
		return true
	}
}

func GetOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func init() {
	rand.Seed(time.Now().Unix())
}

func GetRandomManageAddr() string {
	//return "106.120.188.251:8082"
	tmpList := make([]string, len(ManageAddrs))

	//return random reachable one
	copy(tmpList, ManageAddrs)
	for len(tmpList) != 0 {
		i := rand.Int() % len(tmpList)
		url := tmpList[i]
		conn, err := net.DialTimeout("tcp", url, 3*time.Second)
		if err != nil {
			tmpList = append(tmpList[:i], tmpList[i+1:]...)
			continue
		}
		_ = conn.Close()
		return url
	}

	// if not reachable one then return first one
	if len(ManageAddrs) >= 1 {
		return ManageAddrs[0]
	}
	return ""
}
