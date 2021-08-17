package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"io/ioutil"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	defaultCAFile1        = "../conf/ca.crt"
	defaultClientKeyFile1 = "../conf/client.key"
	defaultClientCrtFile1 = "../conf/client.crt"

	tlsServerName1 = "elkeid.com"
	ServerPort     = "10.227.2.103:6751"
	AgentCount     = 1
)

func main() {
	port := ServerPort
	certificate, err := tls.LoadX509KeyPair(defaultClientCrtFile1, defaultClientKeyFile1)
	if err != nil {
		fmt.Println(err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(defaultCAFile1)
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
		ServerName:         tlsServerName1, // NOTE: this is required!
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	})

	conn, _ := grpc.Dial(
		port, grpc.WithTransportCredentials(creds), grpc.WithTimeout(10*time.Second),
	)
	for i := 0; i < AgentCount; i++ {
		go Transfer(conn, fmt.Sprintf("4442222-3365-4905-b417-331e18333%d", i), fmt.Sprintf("10.10.85.%d", i), fmt.Sprintf("10-10-85-%d", i))
	}
	select {}
}

func Transfer(conn *grpc.ClientConn, agentID, ip, hostname string) {
	c := pb.NewTransferClient(conn)
	client, err := c.Transfer(context.Background())
	if err != nil {
		fmt.Println("Transfer error ", err)
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		i := 0
		for {
			i++
			data, err := client.Recv()
			if err != nil {
				fmt.Println("recv err:", err)
				break
			}
			fmt.Printf("recv AgentCtrl:%v Task:%v Config:%v\n", data.AgentCtrl, data.Task, data.Config)
		}
		wg.Done()
	}()

	datas := make([]*pb.Record, 0)
	datas_hb := make([]*pb.Record, 0)
	for i := 0; i <= 1; i++ {
		tmp := &pb.Record{Message: map[string]string{"data_type": "1000", "cpu": "0.11", "version": "1.6.0.0", "memory": "24324432", "net_type": "boe", "io": "32.2", "slab": "324325435454"}}
		datas_hb = append(datas_hb, tmp)
	}
	for i := 0; i <= 1000; i++ {
		tmp := &pb.Record{Message: map[string]string{"data_type": "5000", "cpu": "0.11", "version": "1.6.0.0", "memory": "24324432", "net_type": "boe", "io": "32.2", "slab": "324325435454"}}
		datas = append(datas, tmp)
	}

	go func() {
		i := 0
		for {
			i++
			if i%30 == 0 {
				data := pb.RawData{
					IntranetIPv4: []string{ip},
					ExtranetIPv4: []string{},
					IntranetIPv6: []string{},
					ExtranetIPv6: []string{},
					Hostname:     hostname,
					AgentID:      agentID,
					Timestamp:    time.Now().Unix(),
					Version:      "1",
					Pkg:          datas_hb,
				}
				err := client.Send(&data)
				if err != nil {
					break
				}
			} else {
				data := pb.RawData{
					IntranetIPv4: []string{ip},
					ExtranetIPv4: []string{},
					IntranetIPv6: []string{},
					ExtranetIPv6: []string{},
					Hostname:     hostname,
					AgentID:      agentID,
					Timestamp:    time.Now().Unix(),
					Version:      "1",
					Pkg:          datas,
				}
				err := client.Send(&data)
				if err != nil {
					break
				}
			}

			fmt.Println("send data!")
			time.Sleep(time.Millisecond * 500)
		}
		wg.Done()
	}()

	wg.Wait()
}
