package kafka

import (
	"fmt"
	"testing"
)

func TestNewConsumer(t *testing.T) {
	p, err := NewConsumer([]string{"127.0.0.1:9092"}, "hids_svr")
	if err != nil {
		fmt.Printf("NewConsumer error: %v", err)
		return
	}

	p.StartConsume()
}
