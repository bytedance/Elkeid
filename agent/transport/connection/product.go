package connection

import _ "embed"

//go:embed client.key
var ClientKey []byte

//go:embed client.crt
var ClientCert []byte

//go:embed ca.crt
var CaCert []byte

func init() {
	sd["findyou-0"] = "10.227.2.103:8098"
	sd["findyou-1"] = "10.227.2.103:8089"
	setDialOptions(CaCert, ClientKey, ClientCert, "elkeid.com")
}
