package httptrans

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/http_handler"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/midware"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io/ioutil"
	"net/http"
	"os"
)

func Run() {
	go runAPIServer(common.HttpPort, common.HttpSSLEnable, common.HttpAuthEnable, common.SSLCertFile, common.SSLKeyFile)
	runRawDataServer(common.RawDataPort, common.SSLCaFile, common.SSLRawDataCertFile, common.SSLRawDataKeyFile)
}

func runAPIServer(port int, enableSSL, enableAuth bool, certFile, keyFile string) {
	router := gin.Default()

	router.GET("/metrics", func(c *gin.Context) {
		promhttp.Handler().ServeHTTP(c.Writer, c.Request)
	})
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	apiGroup := router.Group("/")
	if enableAuth {
		apiGroup.Use(midware.AKSKAuth())
	}

	{
		apiGroup.GET("/conn/stat", http_handler.ConnStat)    //Get conn status
		apiGroup.GET("/conn/list", http_handler.ConnList)    //Get agentID list
		apiGroup.GET("/conn/count", http_handler.ConnCount)  //Get the total number of conn
		apiGroup.POST("/conn/reset", http_handler.ConnReset) //Disconnect the agent

		apiGroup.GET("/conn/limit", http_handler.GetConnLimit)
		apiGroup.POST("/conn/limit", http_handler.UpdateConnLimit)

		apiGroup.POST("/command/", http_handler.PostCommand) //Post commands to the agent

		apiGroup.GET("/kube/cluster/list", http_handler.ClusterList)

		apiGroup.POST("/config/update", http_handler.UpdateAgentConfig)
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

func runRawDataServer(port int, caFile, certFile, keyFile string) {
	router := gin.Default()
	rawDataGroup := router.Group("/rawdata")
	{
		rawDataGroup.POST("/audit", http_handler.RDAudit) //Save audit log from k8s cluster
	}

	var err error
	tlsConfig := credential(certFile, keyFile, caFile)
	if tlsConfig == nil {
		ylog.Errorf("RunRawDataServer", "####GET_CREDENTIAL_ERROR")
		os.Exit(-1)
	}
	server := http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	ylog.Infof("RunRawDataServer", "####RAW_DATA_HTTP_LISTEN_ON:%d", port)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		ylog.Errorf("RunRawDataServer", "####raw_data http run error: %v", err)
	}
}

// Get the encryption certificate
func credential(crtFile, keyFile, caFile string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		ylog.Errorf("Credential", "LOAD_X509_ERROR:%s crtFile:%s keyFile:%s", err.Error(), crtFile, keyFile)
		return nil
	}

	caBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		ylog.Errorf("Credential", "READ_CAFILE_ERROR:%s caFile:%s", err.Error(), caFile)
		return nil
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caBytes); !ok {
		ylog.Errorf("Credential", "####APPEND_CERT_ERROR: %v", err)
		return nil
	}
	return &tls.Config{ClientCAs: certPool, ClientAuth: tls.RequireAndVerifyClientCert, Certificates: []tls.Certificate{cert}}
}
