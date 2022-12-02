package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	mg "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"io/ioutil"
	"math/rand"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	defaultCAFile2        = "../conf/ca.crt"
	defaultClientKeyFile2 = "../conf/client.key"
	defaultClientCrtFile2 = "../conf/client.crt"

	tlsServerName2 = "elkeid.com"
	ServerPort2    = "127.0.0.1:6751"
)

func main() {
	certificate, err := tls.LoadX509KeyPair(defaultClientCrtFile2, defaultClientKeyFile2)
	if err != nil {
		fmt.Println(err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(defaultCAFile2)
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
		ServerName:         tlsServerName2, // NOTE: this is required!
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	})

	for i := 0; i < 1; i++ {
		conn, _ := grpc.Dial(
			ServerPort2, grpc.WithTransportCredentials(creds), grpc.WithTimeout(10*time.Second),
		)
		go uploadFile(conn, "./test.sh")
	}

	select {}
}

func uploadFile(conn *grpc.ClientConn, filename string) {
	c := mg.NewFileExtClient(conn)
	client, err := c.Upload(context.Background())
	if err != nil {
		fmt.Println("uploadFile error ", err)
		return
	}

	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("uploadFile error ", err)
		return
	}

	data := &mg.UploadRequest{
		Token: fmt.Sprintf("hids_test_file_%d_%d", time.Now().UnixNano(), rand.Int()),
		Data:  fileData,
	}
	fmt.Printf("sent toke %s\n", data.Token)
	err = client.Send(data)
	if err != nil {
		fmt.Println("uploadFile error ", err)
		return
	}

	req, err := client.CloseAndRecv()
	if err != nil {
		fmt.Println("uploadFile error ", err)
		return
	}
	fmt.Printf("uploadFile send ok and recv %d\n", req.Status)
	return
}
