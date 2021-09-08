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
	"io/ioutil"
	"net/http"
	"os"
)

func Run() {
	go runApiServer(common.HttpPort, common.HttpSSLEnable, common.HttpAuthEnable, common.SSLCertFile, common.SSLKeyFile)
	runRawDataServer(common.RawDataPort, common.SSLCaFile, common.SSLCertFile, common.SSLKeyFile)
}

// Get the encryption certificate
func credential(crtFile, keyFile, caFile string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		fmt.Printf("Credential LOAD_X509_ERROR:%s crtFile:%s keyFile:%s \n", err.Error(), crtFile, keyFile)
		return nil
	}

	caBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		fmt.Printf("Credential READ_CAFILE_ERROR:%s caFile:%s\n", err.Error(), caFile)
		return nil
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caBytes); !ok {
		fmt.Printf("Credential ####APPEND_CERT_ERROR: %v\n", err)
		return nil
	}
	return &tls.Config{ClientCAs: certPool, ClientAuth: tls.RequireAndVerifyClientCert, Certificates: []tls.Certificate{cert}}
}

func runApiServer(port int, enableSSL, enableAuth bool, certFile, keyFile string) {
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
		rawDataGroup.POST("/audit/:cluster", http_handler.RDAudit) //Save audit log from k8s cluster
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

	fmt.Printf("RunRawDataServer ####RAW_DATA_HTTP_LISTEN_ON:%d\n", port)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		ylog.Errorf("RunRawDataServer", "####raw_data http run error: %v", err)
	}
}
