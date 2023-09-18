package http_handler

import (
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/grpc_handler"
	"github.com/gin-gonic/gin"
)

func UpdateAgentConfig(c *gin.Context) {
	var req []*common.ConfigReleaseInfo
	err := c.BindJSON(&req)
	if err != nil {
		CreateResponse(c, ParamInvalidErrorCode, err.Error())
		ylog.Errorf("UpdateAgentConfig", ">>>> Parse para error : %s", err.Error())
		return
	}

	if grpc_handler.GlobalConfigHandler == nil {
		CreateResponse(c, UnknownErrorCode, "GlobalConfigHandler is nil")
		ylog.Errorf("UpdateAgentConfig", "GlobalConfigHandler is nil")
		return
	}

	//校验&拉取配置
	grpc_handler.GlobalConfigHandler.VerifyAndUpdateRelease(req)
	CreateResponse(c, SuccessCode, "ok")
	return
}
