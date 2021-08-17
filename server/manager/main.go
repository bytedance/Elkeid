package main

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"os/signal"
	"syscall"
)

func init() {
	signal.Notify(infra.Sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
}

func main() {
	//register server
	reg := discovery.NewServerRegistry()
	defer reg.Stop()

	//start server
	go ServerStart()

	<-infra.Sig
	close(infra.Quit)
}

func ServerStart() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	biz.RegisterRouter(router)
	go func() {
		ylog.Infof("[START_SERVER]", "Listening and serving on :%d", infra.HttpPort)
		err := router.Run(fmt.Sprintf(":%d", infra.HttpPort))
		ylog.Errorf("SRV_ERROR", err.Error())
	}()

	select {
	case <-infra.Quit:
		return
	}
}
