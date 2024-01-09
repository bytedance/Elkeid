package handler

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/cluster"
	"github.com/bytedance/Elkeid/server/service_discovery/common"
	"github.com/bytedance/Elkeid/server/service_discovery/common/ylog"
	"github.com/bytedance/Elkeid/server/service_discovery/endpoint"
)

var (
	CI cluster.Cluster
	EI *endpoint.Endpoint
)

func init() {
	CI = cluster.NewConfigCluster(fmt.Sprintf("%s:%d", common.SrvIp, common.SrvPort), common.RunMode)
	EI = endpoint.NewEndpoint(CI)
	ylog.Infof("init", "NewConfigCluster & NewEndpoint end!")
}
