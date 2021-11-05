package main

import (
	context "context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// COPY ME FROM ../transport/connection/client.key
//go:embed client.key
var ClientKey []byte

// COPY ME FROM ../transport/connection/client.crt
//go:embed client.crt
var ClientCert []byte

// COPY ME FROM ../transport/connection/ca.crt
//go:embed ca.crt
var CaCert []byte

func main() {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(CaCert)
	keyPair, _ := tls.X509KeyPair(ClientCert, ClientKey)
	dialOptions := []grpc.DialOption{}
	dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keyPair},
		// EDIT ServerName WITH ../transport/connection/product.go
		ServerName: "elkeid.com",
		ClientAuth: tls.RequireAndVerifyClientCert,
		RootCAs:    certPool,
	})))
	// EDIT Target WITH ../transport/connection/product.go
	conn, err := grpc.Dial("127.0.0.1:8080", dialOptions...)
	if err != nil {
		fmt.Println(err)
		return
	}
	client := NewTransferClient(conn)
	_, err = client.Transfer(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
}
