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
	return ManageAddrs[rand.Intn(len(ManageAddrs))]

}
