package infra

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

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

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func Contains(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

var mutex sync.Mutex

func DistributedLock(key string) (bool, error) {
	mutex.Lock()
	defer mutex.Unlock()
	bool, err := Grds.SetNX(context.Background(), fmt.Sprintf("DistributedLock-%s", key), 1, 10*time.Second).Result()
	if err != nil {
		return false, err
	}
	return bool, nil
}

func DistributedUnLock(key string) error {
	_, err := Grds.Del(context.Background(), fmt.Sprintf("DistributedLock-%s", key)).Result()
	if err != nil {
		return err
	}
	return nil
}
