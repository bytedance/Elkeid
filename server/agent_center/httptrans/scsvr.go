package httptrans

import (
	"crypto/tls"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/midware"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func Run() {
	runServer(common.HttpPort, common.HttpSSLEnable, common.HttpAuthEnable, common.SSLCertFile, common.SSLKeyFile)
}

func runServer(port int, enableSSL, enableAuth bool, certFile, keyFile string) {
	router := gin.Default()

	apiGroup := router.Group("/")
	if enableAuth {
		apiGroup.Use(midware.AKSKAuth())
	}

	{
		apiGroup.GET("/conn/stat", http_handler.ConnStat)    //Get conn status
		apiGroup.GET("/conn/list", http_handler.ConnList)    //Get agentID list
		apiGroup.GET("/conn/count", http_handler.ConnCount)  //Get the total number of conn
		apiGroup.POST("/conn/reset", http_handler.ConnReset) //Disconnect the agent

		apiGroup.POST("/command/", http_handler.PostCommand) //Post commands to the agent
	}

	ylog.Infof("RunServer", "####HTTP_LISTEN_ON:%d", port)
	if enableSSL {
		secCipherSuites := make([]uint16, 0, 0)
		for _, c := range tls.CipherSuites() {
			secCipherSuites = append(secCipherSuites, c.ID)
		}

		// 创建自定义的TLS配置
		tlsConfig := &tls.Config{
			// 禁用不安全的加密套件
			CipherSuites:     secCipherSuites,
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}

		// 创建http.Server实例
		server := &http.Server{
			Addr:      fmt.Sprintf(":%d", port),
			Handler:   router,
			TLSConfig: tlsConfig, // 将自定义的TLS配置应用到http.Server上
		}

		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			if err == http.ErrServerClosed {
				// 服务器被正常关闭
				log.Printf("Server closed: %v", err)
			} else {
				ylog.Errorf("RunServer", "####http run error: %v", err)
			}
		}
	} else {
		err := router.Run(fmt.Sprintf(":%d", port))
		if err != nil {
			ylog.Errorf("RunServer", "####http run error: %v", err)
		}
	}
}
