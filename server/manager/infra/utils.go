package infra

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"math/rand"
	"net"
	"sync"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func GetOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = conn.Close()
	}()
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

func DistributedLockWithExpireTime(key string, expireTime time.Duration) (bool, error) {
	mutex.Lock()
	defer mutex.Unlock()
	ok, err := Grds.SetNX(context.Background(), fmt.Sprintf("DistributedLock-%s", key), 1, expireTime).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

func DistributedUnLock(key string) error {
	_, err := Grds.Del(context.Background(), fmt.Sprintf("DistributedLock-%s", key)).Result()
	if err != nil {
		return err
	}
	return nil
}

func DistributedUnLockWithRetry(key string, retry int) (err error) {
	rKey := fmt.Sprintf("DistributedLock-%s", key)
	for {
		retry--
		_, err = Grds.Del(context.Background(), rKey).Result()
		if err == nil {
			return nil
		}
		ylog.Errorf("DistributedUnLockWithRetry", "key %s, error %s.", rKey, err.Error())
		if retry < 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	return err
}

func Union(slice1, slice2 []string) []string {
	res := make([]string, 0, len(slice1)+len(slice2))
	m := make(map[string]struct{})
	for _, v := range slice1 {
		if _, ok := m[v]; !ok {
			res = append(res, v)
			m[v] = struct{}{}
		}
	}
	for _, v := range slice2 {
		if _, ok := m[v]; !ok {
			res = append(res, v)
			m[v] = struct{}{}
		}
	}
	return res
}
