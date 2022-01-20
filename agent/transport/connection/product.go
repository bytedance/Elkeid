//go:build product
// +build product

package connection

import (
	_ "embed"
	"os"
)

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
	if idc, ok := os.LookupEnv("specified_idc"); ok {
		IDC.Store(idc)
	} else {
		IDC.Store("default")
	}
	Region.Store("default")
}
