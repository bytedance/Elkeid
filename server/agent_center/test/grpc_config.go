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

var (
	defaultCAFile1        = "../conf/ca.crt"
	defaultClientKeyFile1 = "../conf/client.key"
	defaultClientCrtFile1 = "../conf/client.crt"

	tlsServerName1 = "elkeid.com"
	ServerPort     = "127.0.0.1:6751"
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
	for i := 0; i < 1; i++ {
		go CheckConfig(conn, fmt.Sprintf("4442222-3365-4905-b417-331e18333%d", i), fmt.Sprintf("plugins_%d", i))
	}
	select {}
}

func CheckConfig(conn *grpc.ClientConn, agentID, pluginName string) {
	c := pb.NewConfigExtClient(conn)

	in := &pb.ConfigRefreshRequest{
		AgentID:     "i-ycbkd9kpuw7grazw5c4a",
		PluginName:  "driver1",
		Fingerprint: make([]*pb.ConfigFingerPrint, 0, 0),
	}
	out, err := c.CheckConfig(context.Background(), in)
	if err != nil {
		fmt.Println("CheckConfig error ", err.Error())
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Println("Marshal error ", err.Error())
		return
	}
	fmt.Println("init check :", out.Status, string(b))
	time.Sleep(time.Second)

	//第二次检测
	in.Fingerprint = append(in.Fingerprint, &pb.ConfigFingerPrint{
		Path:   "config/block_md5.json",
		Hash:   "c297905e950ac74547c47ee5a057748c",
		Status: 0,
	})
	in.Fingerprint = append(in.Fingerprint, &pb.ConfigFingerPrint{
		Path:   "config/block_exe_argv.json",
		Hash:   "ea56859a0681b5fd7a1a1dbfc1e56a03",
		Status: 0,
	})
	out2, err := c.CheckConfig(context.Background(), in)
	if err != nil {
		fmt.Println("CheckConfig error ", err.Error())
		return
	}
	b2, err := json.Marshal(out2)
	if err != nil {
		fmt.Println("Marshal error ", err.Error())
		return
	}
	fmt.Println("init check :", out2.Status, string(b2))
	time.Sleep(time.Second)

	//第三次检测
	in.Fingerprint = append(in.Fingerprint, &pb.ConfigFingerPrint{
		Path:   "config/block_md52.json",
		Hash:   "c297905e950ac74547c47ee5a057748c112",
		Status: 0,
	})
	out3, err := c.CheckConfig(context.Background(), in)
	if err != nil {
		fmt.Println("CheckConfig error ", err.Error())
		return
	}
	b3, err := json.Marshal(out3)
	if err != nil {
		fmt.Println("Marshal error ", err.Error())
		return
	}
	fmt.Println("init check :", out2.Status, string(b3))
}

//{
//                "path": "config/block_md5.json",
//                "status": 1,
//                "data": "[[{\"Key\":\"ID\",\"Value\":\"EL000001\"},{\"Key\":\"FileType\",\"Value\":\"ELF\"},{\"Key\":\"FileMD5\",\"Value\":\"cd16f4f54bca5ae63419abe106584ba8\"},{\"Key\":\"M2MD5\",\"Value\":\"cd16f4f54bca5ae63419abe106584ba8\"},{\"Key\":\"Size\",\"Value\":113585},{\"Key\":\"MaliciousName\",\"Value\":\"Unix.Malware.Agent-6904893-0\"}]]",
//                "type": 1,
//                "detail": "",
//                "hash": "c297905e950ac74547c47ee5a057748c"
//            },
//            {
//                "path": "config/block_exe_argv.json",
//                "status": 1,
//                "data": "[[{\"Key\":\"Exe\",\"Value\":\"\"},{\"Key\":\"Argv\",\"Value\":\"\"},{\"Key\":\"MaliciousName\",\"Value\":\"\"},{\"Key\":\"ID\",\"Value\":\"PR000001\"}],[{\"Key\":\"Argv\",\"Value\":\"\"},{\"Key\":\"MaliciousName\",\"Value\":\"\"},{\"Key\":\"ID\",\"Value\":\"PR000011\"},{\"Key\":\"Exe\",\"Value\":\"\"}]]",
//                "type": 1,
//                "detail": "",
//                "hash": "ea56859a0681b5fd7a1a1dbfc1e56a03"
//            }
