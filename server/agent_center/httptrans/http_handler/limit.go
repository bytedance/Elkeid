package http_handler

import (
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/grpc_handler"
	"github.com/gin-gonic/gin"
)

type LimitRequest struct {
	TargetValue *int32 `json:"target_value" binding:"required" `
	LastSecond  *int64 `json:"last_second" binding:"required" `
}

func GetConnLimit(c *gin.Context) {
	val, sec := grpc_handler.GlobalGRPCPool.GetDynamicLimit()
	res := map[string]interface{}{
		"target_value":  val,
		"last_second":   sec,
		"current_value": grpc_handler.GlobalGRPCPool.GetCount(),
		"max_value":     common.ConnLimit,
	}
	CreateResponse(c, SuccessCode, res)
	return
}

func UpdateConnLimit(c *gin.Context) {
	var param LimitRequest
	err := c.BindJSON(&param)
	if err != nil {
		ylog.Errorf("UpdateConnLimit", ">>>> Parse para error : %s", err.Error())
		CreateResponse(c, ParamInvalidErrorCode, err.Error())
		return
	}

	if *param.LastSecond <= 0 {
		CreateResponse(c, ParamInvalidErrorCode, "last_second must > 0.")
		return
	}
	if *param.TargetValue < 0 {
		CreateResponse(c, ParamInvalidErrorCode, "target_value must >= 0.")
		return
	}

	grpc_handler.GlobalGRPCPool.SetDynamicLimit(*param.TargetValue, *param.LastSecond)

	res := gin.H{}
	detail := gin.H{}
	conn := grpc_handler.GlobalGRPCPool.GetList()
	resetCount := len(conn) - int(*param.TargetValue)
	if resetCount > 0 {
		id := 0
		for id = 0; id < resetCount; id++ {
			agentID := conn[id].AgentID
			err := grpc_handler.GlobalGRPCPool.Close(agentID)
			if err != nil {
				detail[agentID] = err.Error()
			} else {
				detail[agentID] = "ok"
			}
		}
		res["reset_count"] = id
		res["reset_detail"] = detail
	}

	CreateResponse(c, SuccessCode, res)
	return
}
