package httptrans

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/midware"
	"github.com/gin-gonic/gin"
)

func Run() {
	runServer(common.HttpPort, common.HttpSSLEnable, common.HttpAuthEnable, common.SSLCertFile, common.SSLKeyFile)
}

func runServer(port int, enableSSL, enableAuth bool, certFile, keyFile string) {
	router := gin.Default()

	connGroup := router.Group("/conn")
	{
		connGroup.GET("/conn/stat", http_handler.ConnStat)    //Get conn status
		connGroup.GET("/conn/list", http_handler.ConnList)    //Get agentID list
		connGroup.GET("/conn/count", http_handler.ConnCount)  //Get the total number of conn
		connGroup.POST("/conn/reset", http_handler.ConnReset) //Disconnect the agent
	}

	commGroup := router.Group("/command")
	{
		commGroup.POST("/", http_handler.PostCommand) //Post commands to the agent
	}

	if enableAuth {
		connGroup.Use(midware.AKSKAuth())
		commGroup.Use(midware.AKSKAuth())
	}

	rawDataGroup := router.Group("/rawdata")
	{
		rawDataGroup.POST("/audit/:cluster", http_handler.RDAudit) //Save audit log from k8s cluster
	}

	var err error
	ylog.Infof("RunServer", "####HTTP_LISTEN_ON:%d", port)
	if enableSSL {
		err = router.RunTLS(fmt.Sprintf(":%d", port), certFile, keyFile)
	} else {
		err = router.Run(fmt.Sprintf(":%d", port))
	}
	if err != nil {
		ylog.Errorf("RunServer", "####http run error: %v", err)
	}
}
