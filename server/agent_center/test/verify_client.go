package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"io/ioutil"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	port := "127.0.0.1:6751"
	agentCount := 1
	certificate, err := tls.LoadX509KeyPair("../conf/client.crt", "../conf/client.key")
	if err != nil {
		fmt.Println(err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("../conf/ca.crt")
	if err != nil {
		fmt.Println(err)
		return
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		fmt.Println("failed to append ca certs")
		return
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{certificate},
		ServerName:         "elkeid.com", // NOTE: this is required!
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	})

	conn, _ := grpc.Dial(
		port, grpc.WithTransportCredentials(creds), grpc.WithTimeout(10*time.Second),
	)
	for i := 0; i < agentCount; i++ {
		go VerifyInstall(conn, fmt.Sprintf("4442222-3365-4905-b417-331e18333%d", i), fmt.Sprintf("key_%d", i))
	}
	select {}
}

func VerifyInstall(conn *grpc.ClientConn, agentID, key string) {
	c := pb.NewVerifyInstallClient(conn)

	in := &pb.VerifyInstallRequest{
		AgentID:     agentID,
		InstallKey:  key,
		InstallType: "install_type_001",
	}
	out, err := c.VerifyInstall(context.Background(), in)
	if err != nil {
		fmt.Println("VerifyInstall error ", err.Error())
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Println("Marshal error ", err.Error())
		return
	}
	fmt.Println("VerifyInstall :", out.Success, string(b))
	time.Sleep(time.Second)
}
