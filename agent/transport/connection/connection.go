package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

var (
	IDC     string
	Region  string
	NetMode = atomic.Value{} //string
)
var (
	conn                 atomic.Value //*grpc.ClientConn
	retries              int32        // use atomic methods
	dialOptions          = []grpc.DialOption{}
	serviceDiscoveryHost = map[string]string{}
	privateHost          = map[string]string{}
	publicHost           = map[string]string{}
)

func init() {
	NetMode.Store("unknown")
}

type content struct {
	Code int32 `json:"code"`
	Data []struct {
		Name     string `json:"name"`
		IP       string `json:"ip"`
		Port0    int    `json:"port0"`
		Port1    int    `json:"port1"`
		Weight   int    `json:"weight"`
		Status   string `json:"status"`
		CreateAt uint64 `json:"create_at"`
		UpdateAt uint64 `json:"update_at"`
	} `json:"data"`
	Msg string `json:"msg"`
}

func resolveService(host string, count int) ([]string, error) {
	serviceDiscoveryURL := url.URL{Scheme: "http", Host: host, Path: "registry/fetch", RawQuery: "name=hids_svr_grpc&count=" + strconv.Itoa(count)}
	resp, err := http.Get(serviceDiscoveryURL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	c := content{}
	err = decoder.Decode(&c)
	if err != nil {
		return nil, err
	}
	if len(c.Data) < 1 {
		return nil, errors.New("no server is available")
	}
	svr := []string{}
	for _, i := range c.Data {
		svr = append(svr, i.IP+":"+strconv.Itoa(i.Port0))
	}
	return svr, nil
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
	})), grpc.WithStatsHandler(&DefaultStatsHandler), grpc.WithBlock())
}

func GetConnection(ctx context.Context) *grpc.ClientConn {
	c, ok := conn.Load().(*grpc.ClientConn)
	if ok {
		switch c.GetState() {
		case connectivity.Ready:
			if atomic.AddInt32(&retries, 1) > 5 {
				c.Close()
			} else {
				return c
			}
		case connectivity.Connecting:
			c.Close()
		case connectivity.Idle:
			if atomic.AddInt32(&retries, 1) > 5 {
				c.Close()
			} else {
				return c
			}
		case connectivity.TransientFailure:
			c.Close()
		case connectivity.Shutdown:
		}
	}
	host, ok := serviceDiscoveryHost[Region]
	if ok {
		addrs, err := resolveService(host, 10)
		if err == nil {
			for _, addr := range addrs {
				context, cancel := context.WithTimeout(ctx, time.Second*3)
				defer cancel()
				c, err := grpc.DialContext(context, addr, dialOptions...)
				if err == nil {
					conn.Store(c)
					NetMode.Store("sd")
					atomic.StoreInt32(&retries, 0)
					return c
				}
			}
		}
	}
	host, ok = privateHost[Region]
	if ok {
		context, cancel := context.WithTimeout(ctx, time.Second*3)
		defer cancel()
		c, err := grpc.DialContext(context, host, dialOptions...)
		if err == nil {
			conn.Store(c)
			NetMode.Store("private")
			atomic.StoreInt32(&retries, 0)
			return c
		}
	}
	host, ok = publicHost[Region]
	if ok {
		context, cancel := context.WithTimeout(ctx, time.Second*3)
		defer cancel()
		c, err := grpc.DialContext(context, host, dialOptions...)
		if err == nil {
			conn.Store(c)
			NetMode.Store("public")
			atomic.StoreInt32(&retries, 0)
			return c
		}
	}
	return nil
}
