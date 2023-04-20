package v1

import (
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/aconfig"
	"github.com/gin-gonic/gin"
)

// GetConfigByID return agent config by agent_id.
func GetConfigByID(c *gin.Context) {
	agentID := c.Param("id")
	conf, err := aconfig.GetConfigByID(agentID)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, conf)
	return
}

// GetDefaultConfig get default agent config
func GetDefaultConfig(c *gin.Context) {
	common.CreateResponse(c, common.SuccessCode, aconfig.GetDefaultConfig())
	return
}

// UpdateDefaultConfig update default agent config
func UpdateDefaultConfig(c *gin.Context) {
	var conf aconfig.DefaultConfig

	err := c.BindJSON(&conf)
	if err != nil {
		ylog.Errorf("UpdateDefaultConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = aconfig.UpdateDefaultConfig(conf)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, conf)
	return
}
