package main

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common/kafka"
)

func main() {
	p, err := kafka.NewConsumer([]string{"10.227.2.103:9092"}, "hids_svr")
	if err != nil {
		fmt.Printf("NewConsumer error: %v\n", err)
		return
	}

	p.StartConsume()
}
