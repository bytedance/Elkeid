package job

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
)

var (
	LocalHost    string
	RegistryHost string
)

func init() {
	LocalHost = fmt.Sprintf("%s:%d", infra.LocalIP, infra.HttpPort)
}
