package kube

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

var caCert *x509.Certificate
var caKey *rsa.PrivateKey
var caByte []byte

func InitCaCert() {
	var err error
	caCert, caKey, err = loadX509KeyPair("./conf/ca.crt", "./conf/ca.key")
	if err != nil {
		fmt.Printf("LoadX509KeyPair Error %s\n", err.Error())
		ylog.Errorf("LoadX509KeyPair", "failed to load ca %s.", err.Error())
		return
	}

	caByte, err = os.ReadFile("./conf/ca.crt")
	if err != nil {
		fmt.Printf("ReadFile CA Error %s\n", err.Error())
		ylog.Errorf("ReadFile CA", "failed to load ca %s.", err.Error())
	}
}

func LoadCaCert() []byte {
	return caByte
}

func CreateCert(commonName string, duration time.Duration) (key, cert []byte, err error) {
	if caCert == nil || caKey == nil {
		return nil, nil, errors.New("ca is not set")
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	key, err = decodeKey(clientKey)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(duration)
	clientTemplate := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(4),
		Subject: pkix.Name{
			Organization: []string{"Elkeid"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert = decodeCert(derBytes)
	return key, cert, nil
}

func loadX509KeyPair(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cf, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	kf, e := os.ReadFile(keyFile)
	if e != nil {
		return nil, nil, e
	}
	cpb, _ := pem.Decode(cf)
	kpb, _ := pem.Decode(kf)
	crt, err := x509.ParseCertificate(cpb.Bytes)
	if e != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kpb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

func decodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil

}

func decodeCert(derBytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}
