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
		// 创建自定义的TLS配置
		tlsConfig := &tls.Config{
			// 禁用不安全的加密套件
			CipherSuites: []uint16{
				// TLS 1.3推荐的密码套件
				tls.TLS_AES_128_GCM_SHA256,       // 适用于需要快速性能的场景
				tls.TLS_AES_256_GCM_SHA384,       // 提供更高级别的安全性
				tls.TLS_CHACHA20_POLY1305_SHA256, // 现代算法，提供良好的安全性和性能

				// TLS 1.2推荐的密码套件，当TLS 1.3不可用时作为备选
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,

				// 如果需要兼容更旧的系统，可以添加以下套件，但请注意它们的安全性不如上述套件
				// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

				// 如果必须支持旧系统，可以考虑以下套件，但它们不如上述GCM套件安全
				// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
			},
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
