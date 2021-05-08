#!/bin/bash
#usage ./cert_gen.sh DNSNAME ObjectName CN
#example ./cert_gen.sh elkeid.com hids-svr elkeid@elkeid.com

if [ $# -lt 3 ]
then
  echo "Usage : $0 DNSNAME ObjectName CN"
  echo "Example : $0 elkeid.com hids-svr elkeid@elkeid.com"
  exit
fi

mkdir cert
cd cert

CA_CONFIG="
[req]
distinguished_name=dn
[ dn ]
[ ext ]
basicConstraints=CA:TRUE,pathlen:0
"

cat << EOF > "v3.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $1
EOF

#ca 证书  /etc/ssl/openssl.cnf
openssl genrsa -out ca.key 2048
openssl req  -config <(echo "$CA_CONFIG") -new -x509 -days 36500 -subj "/C=GB/L=China/O=$2/CN=$3" -key ca.key -out ca.crt
openssl x509 -noout -text -in ca.crt

#server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/C=GB/L=China/O=$2/CN=$3"  -out server.csr
openssl x509 -req -sha256 -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -in server.csr -extfile "v3.ext" -out server.crt
openssl x509 -noout -text -in server.crt

#agent
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/C=GB/L=China/O=$2/CN=$3"  -out client.csr
openssl x509 -req -sha256 -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -in client.csr -extfile "v3.ext" -out client.crt
openssl x509 -noout -text -in client.crt

rm -rf v3.ext ca.srl client.csr server.csr
cd ../
