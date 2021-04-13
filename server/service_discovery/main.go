package main

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/common"
	"github.com/bytedance/Elkeid/server/service_discovery/server"
)

func main() {

	go server.ServerStart(common.SrvIp, common.SrvPort)

	<-common.Quit

	fmt.Printf("game over ...\n")
	return
}
