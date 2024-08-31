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
		go SendHeartbeat(conn, fmt.Sprintf("proxy_id_%d", i), fmt.Sprintf("4442222-3365-4905-b417-331e18333%d", i))
	}
	select {}
}

func SendHeartbeat(conn *grpc.ClientConn, proxyID, proxyLocalID string) {
	c := pb.NewProxyHeartbeatClient(conn)

	in := &pb.HeartbeatRequest{
		ProxyID:         proxyID,
		ProxyLocalID:    proxyLocalID,
		IntranetIPv4:    nil,
		ExtranetIPv4:    nil,
		IntranetIPv6:    nil,
		ExtranetIPv6:    nil,
		Hostname:        "",
		Version:         "",
		ConnectedAgents: nil,
		ProxyStartTime:  0,
		ProxyStatus:     0,
		StatusMessage:   "",
		DetailedStatus:  map[string]string{"cpu": "0.9"},
	}
	out, err := c.SendHeartbeat(context.Background(), in)
	if err != nil {
		fmt.Println("SendHeartbeat error ", err.Error())
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Println("Marshal error ", err.Error())
		return
	}
	fmt.Println("SendHeartbeat :", out.Status, string(b))
	time.Sleep(time.Second)
}
