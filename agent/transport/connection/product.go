//go:build product
// +build product

package connection

import _ "embed"

//go:embed client.key
var ClientKey []byte

//go:embed client.crt
var ClientCert []byte

//go:embed ca.crt
var CaCert []byte

func init() {
	serviceDiscoveryHost["default"] = "127.0.0.1:8088"
	privateHost["default"] = "127.0.0.1:6751"
	setDialOptions(CaCert, ClientKey, ClientCert, "elkeid.com")
	Region = "default"
	IDC = "default"
}
