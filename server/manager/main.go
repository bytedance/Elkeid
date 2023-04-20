package main

import (
	"fmt"
	initialize "github.com/bytedance/Elkeid/server/manager/init"
	"os"
	"os/signal"
	"syscall"

	"github.com/bytedance/Elkeid/server/manager/biz"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
)

func init() {
	signal.Notify(infra.Sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
}

func main() {
	err := initialize.Initialize()
	if err != nil {
		fmt.Printf("Initialize Error %s\n", err.Error())
		os.Exit(-1)
	}

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
