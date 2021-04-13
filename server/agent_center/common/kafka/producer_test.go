package kafka

import (
	"fmt"
	"testing"
	"time"
)

func TestNewProducer(t *testing.T) {
	big := map[string]string{
		"111": "222",
		"222": "222",
		"333": "222",
	}
	sma := map[string]string{
		"111": "666",
	}
	b, _ := BSerialize(big)
	fmt.Println(string(b))
	bytesPool.Put(b)

	b, _ = BSerialize(sma)
	fmt.Println(string(b))
	bytesPool.Put(b)

	b, _ = BSerialize(big)
	fmt.Println(string(b))
	bytesPool.Put(b)

	b, _ = BSerialize(sma)
	fmt.Println(string(b))
	return
	p, err := NewProducer([]string{"127.0.0.1:9092"}, "hids_svr", "default")
	if err != nil {
		fmt.Printf("NewProducer error: %v", err)
		return
	}

	i := 0
	for {
		p.SendWithKey("testdata", []byte("testdata"))
		i++
		if i >= 100 {
			break
		}
	}
	time.Sleep(100 * time.Second)
}
