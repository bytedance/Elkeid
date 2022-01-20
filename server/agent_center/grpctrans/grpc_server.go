package grpctrans

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/grpc_handler"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"os"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	_ "github.com/bytedance/Elkeid/server/agent_center/common/snappy"
	_ "github.com/bytedance/Elkeid/server/agent_center/common/zstd"
	_ "google.golang.org/grpc/encoding/gzip"
)

const (
	// If the client pings the server multiple times within MinPingTIme time,
	// the connection will be terminated
	defaultMinPingTime = 5 * time.Second

	// Maximum connection idle time
	defaultMaxConnIdle = 20 * time.Minute

	//If the connection is idle during pingtime,
	//the server takes the initiative to ping http_client
	defaultPingTime = 10 * time.Minute

	//Same as above, the timeout period of server waiting for ack when pinging client
	defaultPingAckTimeout = 5 * time.Second

	maxMsgSize = 1024 * 1024 * 10 // grpc maximum message size:10M
)

func Run() {
	grpc_handler.InitGlobalGRPCPool()
	runServer(true, common.GRPCPort, common.SSLCertFile, common.SSLKeyFile, common.SSLCaFile)
}

// Get the encryption certificate
func credential(crtFile, keyFile, caFile string) credentials.TransportCredentials {
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

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	})
}

//start grpc server
// - enableCA: Whether to enable ssl
func runServer(enableCA bool, port int, crtFile, keyFile, caFile string) {
	// Handling client timeout
	kaep := keepalive.EnforcementPolicy{
		MinTime:             defaultMinPingTime,
		PermitWithoutStream: true,
	}

	kasp := keepalive.ServerParameters{
		MaxConnectionIdle: defaultMaxConnIdle,
		Time:              defaultPingTime,
		Timeout:           defaultPingAckTimeout,
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),

		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
	}

	if enableCA {
		ct := credential(crtFile, keyFile, caFile)
		if ct == nil {
			ylog.Errorf("RunServer", "####GET_CREDENTIAL_ERROR")
			os.Exit(-1)
		}
		opts = append(opts, grpc.Creds(ct))
	}

	server := grpc.NewServer(opts...)
	pb.RegisterTransferServer(server, &grpc_handler.TransferHandler{})
	reflection.Register(server)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		ylog.Errorf("RunServer", "####TCP_LISTEN_ERROR: %v", err)
		os.Exit(-1)
	}

	ylog.Infof("RunServer", "####TCP_LISTEN_OK: %v", lis.Addr().String())
	fmt.Printf("####TCP_LISTEN_OK: %v\n", lis.Addr().String())
	if err = server.Serve(lis); err != nil {
		ylog.Errorf("RunServer", "####GRPC_SERVER_ERROR: %v", err)
		os.Exit(-1)
	}
}
