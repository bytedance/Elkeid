package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/golang/protobuf/proto"
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
	AgentCount     = 10
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

	hbData := make([]*pb.Record, 0)
	for i := 0; i <= 0; i++ {
		item := &pb.Item{Fields: map[string]string{"data_type": "1000", "cpu": "0.11", "version": "1.7.0.0", "memory": "24324432", "net_type": "boe", "io": "32.2", "slab": "324325435454"}}
		b, _ := proto.Marshal(item)
		tmp := &pb.Record{Timestamp: time.Now().Unix(), DataType: 1000, Body: b}
		hbData = append(hbData, tmp)

		item = &pb.Item{Fields: map[string]string{"name": "driver", "cpu": "0.11", "version": "1.7.0.0", "memory": "24324432", "net_type": "boe", "io": "32.2", "slab": "324325435454"}}
		b, _ = proto.Marshal(item)
		tmp = &pb.Record{Timestamp: time.Now().Unix(), DataType: 1001, Body: b}
		hbData = append(hbData, tmp)

		item = &pb.Item{Fields: map[string]string{"name": "collector", "cpu": "0.11", "version": "1.7.0.0", "memory": "24324432", "net_type": "boe", "io": "32.2", "slab": "324325435454"}}
		b, _ = proto.Marshal(item)
		tmp = &pb.Record{Timestamp: time.Now().Unix(), DataType: 1001, Body: b}
		hbData = append(hbData, tmp)
	}

	driverData := make([]*pb.Record, 0)
	for i := 0; i <= 100; i++ {
		item := &pb.Item{Fields: map[string]string{"argv": "docker-untar / /data00/dockere/docker/overlay2/0d452e185fc8d39c47bf04084079e16337e0c25ced3dd65ab4571cd4b932f2/diff", "comm": "exe", "dip": "-1", "dport": "-1", "exe": "/usr/bin/dockerd", "exe_hash": "-3", "file_path": "/docker_workplace/docker/overlay2/0d452e185fbac8d39c47bf04084079e16337e0c25ced3dd65ab41cd4b932f2/diff/usr/src/linux-headers-4.15.0-30-generic/include/config/usb/r8a66597.h", "nodename": "n225-085-027", "pgid": "4110146", "pgid_argv": "/usr/bin/dockerd", "pid": "3855481", "pid_tree": "3855481.exe<4110146.dockerd<1.systemd", "pns": "4026531836", "pod_name": "", "ppid": "4110146", "ppid_argv": "/usr/bin/dockerd", "psm": "", "root_pns": "4026531836", "sa_family": "-1", "sessionid": "4294967295", "sid": "4110146", "sip": "-1", "socket_argv": "-3", "socket_pid": "-1", "sport": "-1", "tgid": "3855481", "uid": "0", "username": "root"}}
		b, _ := proto.Marshal(item)
		tmp := &pb.Record{Timestamp: time.Now().Unix(), DataType: 59, Body: b}
		driverData = append(driverData, tmp)
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
					Version:      "1",
					Data:         hbData,
					Product:      "",
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
					Version:      "1",
					Data:         driverData,
					Product:      "",
				}
				err := client.Send(&data)
				if err != nil {
					break
				}
			}

			fmt.Println("send data!")
			time.Sleep(time.Second * 1)
		}
		wg.Done()
	}()

	wg.Wait()
}
