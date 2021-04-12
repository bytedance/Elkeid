package connection

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	sd          = map[string]string{}
	priLB       = map[string]string{}
	pubLB       = map[string]string{}
	dialOptions = []grpc.DialOption{}
)

type service struct {
	Code int32 `json:"code"`
	Data []struct {
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Weight int    `json:"weight"`
	} `json:"data"`
	Msg string `json:"msg"`
}

func setDialOptions(ca, privkey, cert []byte, svrName string) {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	keyPair, _ := tls.X509KeyPair(cert, privkey)
	dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keyPair},
		ServerName:   svrName,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      certPool,
	})), grpc.WithBlock(), grpc.WithTimeout(time.Second*2))
}

func getService(host string) (string, error) {
	findyouURL := url.URL{Scheme: "http", Host: host, Path: "registry/detail", RawQuery: "name=hids_svr_grpc&count=5"}
	resp, err := http.Get(findyouURL.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	svr := service{}
	err = decoder.Decode(&svr)
	if err != nil {
		return "", err
	}
	if len(svr.Data) > 0 {
		minWeight := svr.Data[0].Weight
		address := svr.Data[0].IP + ":" + strconv.Itoa(svr.Data[0].Port)
		for _, i := range svr.Data {
			if i.Weight <= minWeight {
				minWeight = i.Weight
				address = svr.Data[0].IP + ":" + strconv.Itoa(svr.Data[0].Port)
			}
		}
		return address, nil
	}
	return "", errors.New("No server is available")
}

func New() (*grpc.ClientConn, string) {
	for k, v := range sd {
		addr, err := getService(v)
		if err != nil {
			continue
		}
		conn, err := grpc.Dial(addr, dialOptions...)
		if err == nil {
			return conn, k
		}
	}
	var minLatency time.Duration
	var selectedConn *grpc.ClientConn
	var selectedName string
	for k, v := range priLB {
		start := time.Now()
		conn, err := grpc.Dial(v, dialOptions...)
		if err == nil {
			latency := time.Since(start)
			if minLatency == 0 || latency <= minLatency {
				minLatency = latency
				if selectedConn != nil {
					selectedConn.Close()
				}
				selectedConn = conn
				selectedName = k
			} else {
				conn.Close()
			}
		}
	}
	if selectedConn != nil {
		return selectedConn, selectedName
	}
	for k, v := range pubLB {
		start := time.Now()
		conn, err := grpc.Dial(v, dialOptions...)
		if err == nil {
			latency := time.Since(start)
			if minLatency == 0 || latency <= minLatency {
				minLatency = latency
				if selectedConn != nil {
					selectedConn.Close()
				}
				selectedConn = conn
				selectedName = k
			} else {
				conn.Close()
			}
		}

	}
	return selectedConn, selectedName
}
