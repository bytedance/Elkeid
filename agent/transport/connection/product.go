package connection

import _ "embed"

//go:embed client.key
var ClientKey []byte

//go:embed client.crt
var ClientCert []byte

//go:embed ca.crt
var CaCert []byte

func init() {
	sd["sd"] = "127.0.0.1:8088"
	priLB["ac"] = "127.0.0.1:6751"
	setDialOptions(CaCert, ClientKey, ClientCert, "elkeid.com")
}
