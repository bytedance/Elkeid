package v1

import (
	"encoding/json"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	dbtask "github.com/bytedance/Elkeid/server/manager/task"
	"github.com/gin-gonic/gin"
)

func NewAsset(c *gin.Context) {
	var newAsset map[string]interface{}
	err := c.BindJSON(&newAsset)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	pData := make([]map[string]interface{}, 0, 10)
	if data, ok := newAsset["data"]; ok {
		if sData, ok := data.(string); ok {
			err := json.Unmarshal([]byte(sData), &pData)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
		}
	}

	newAsset["data"] = pData
	newAsset["leader_time"] = time.Now().Unix()
	dbtask.HubAssetAsyncWrite(newAsset)
	common.CreateResponse(c, common.SuccessCode, "ok")
}
