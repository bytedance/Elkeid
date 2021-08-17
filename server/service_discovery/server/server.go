package server

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/common"
	"github.com/bytedance/Elkeid/server/service_discovery/common/ylog"
	"github.com/bytedance/Elkeid/server/service_discovery/server/handler"
	"github.com/gin-gonic/gin"
)

func ServerStart(ip string, port int) {
	//new engine
	r := gin.Default()
	//register router
	register(r)
	//run server
	go func() {
		ylog.Infof("[START_SERVER]", "Listening and serving on :%s:%d\n", ip, port)
		fmt.Printf("server run error: %s\n", r.Run(fmt.Sprintf("%s:%d", ip, port)).Error())
	}()

	select {
	case <-common.Sig:
		handler.EI.Stop()
		handler.CI.Stop()
		close(common.Quit)
	}
}
