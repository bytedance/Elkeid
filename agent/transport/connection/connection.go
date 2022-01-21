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
	IDC     = atomic.Value{} //string
	Region  = atomic.Value{} //string
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
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Weight int    `json:"weight"`
	} `json:"data"`
	Msg string `json:"msg"`
}

func LookupRegion(r string) bool {
	_, ok1 := serviceDiscoveryHost[r]
	_, ok2 := privateHost[r]
	_, ok3 := publicHost[r]
	return ok1 || ok2 || ok3
}

func resolveServiceDiscovery(host string, count int) ([]string, error) {
	serviceDiscoveryURL := url.URL{Scheme: "http", Host: host, Path: "registry/detail", RawQuery: "name=hids_svr_grpc&count=" + strconv.Itoa(count)}
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
		svr = append(svr, i.IP+":"+strconv.Itoa(i.Port))
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
	})), grpc.WithStatsHandler(&DefaultStatsHandler), grpc.WithBlock(), grpc.WithReturnConnectionError(), grpc.FailOnNonTempDialError(true))
}

func GetConnection(ctx context.Context) (*grpc.ClientConn, error) {
	c, ok := conn.Load().(*grpc.ClientConn)
	if ok {
		switch c.GetState() {
		case connectivity.Ready:
			if atomic.AddInt32(&retries, 1) > 5 {
				c.Close()
			} else {
				return c, nil
			}
		case connectivity.Connecting:
			c.Close()
		case connectivity.Idle:
			if atomic.AddInt32(&retries, 1) > 5 {
				c.Close()
			} else {
				return c, nil
			}
		case connectivity.TransientFailure:
			c.Close()
		case connectivity.Shutdown:
		}
	}
	region, ok := Region.Load().(string)
	if !ok {
		return nil, errors.New("no available region")
	}
	var err error
	host, ok := serviceDiscoveryHost[region]
	if ok {
		var addrs []string
		addrs, err = resolveServiceDiscovery(host, 10)
		if err == nil {
			for _, addr := range addrs {
				context, cancel := context.WithTimeout(ctx, time.Second*3)
				defer cancel()
				c, err = grpc.DialContext(context, addr, dialOptions...)
				if err == nil {
					conn.Store(c)
					NetMode.Store("sd")
					atomic.StoreInt32(&retries, 0)
					return c, nil
				}
			}
		}
	}
	host, ok = privateHost[region]
	if ok {
		context, cancel := context.WithTimeout(ctx, time.Second*3)
		defer cancel()
		c, err = grpc.DialContext(context, host, dialOptions...)
		if err == nil {
			conn.Store(c)
			NetMode.Store("private")
			atomic.StoreInt32(&retries, 0)
			return c, nil
		}
	}
	host, ok = publicHost[region]
	if ok {
		context, cancel := context.WithTimeout(ctx, time.Second*3)
		defer cancel()
		c, err = grpc.DialContext(context, host, dialOptions...)
		if err == nil {
			conn.Store(c)
			NetMode.Store("public")
			atomic.StoreInt32(&retries, 0)
			return c, nil
		}
	}
	return nil, err
}
