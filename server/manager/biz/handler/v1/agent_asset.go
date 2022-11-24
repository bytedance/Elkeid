package v1

import (
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/bytedance/Elkeid/server/manager/internal/rasp"
	"github.com/gin-gonic/gin"
)

func NewAsset(c *gin.Context) {
	var newAsset map[string]interface{}
	err := c.BindJSON(&newAsset)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	dataType, ok := newAsset["data_type"].(string)
	if !ok {
		return
	}

	switch dataType {
	case "2997", "2996":
		raspHb, err := rasp.RaspHbFormat(newAsset)
		if err != nil {
			return
		}
		go dbtask.LeaderRaspAsyncWrite(newAsset)
		rasp.RaspHbDeal(raspHb)
	default:
		dbtask.HubAssetAsyncWrite(newAsset)
	}
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func BulkNewAsset(c *gin.Context) {
	var newAsset = make([]map[string]interface{}, 0, 100)
	err := c.BindJSON(&newAsset)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	for k := range newAsset {
		dataType, ok := newAsset[k]["data_type"].(string)
		if !ok {
			return
		}

		switch dataType {
		case "2997", "2996":
			raspHb, err := rasp.RaspHbFormat(newAsset[k])
			if err != nil {
				continue
			}
			go dbtask.LeaderRaspAsyncWrite(newAsset[k])
			rasp.RaspHbDeal(raspHb)
		default:
			dbtask.HubAssetAsyncWrite(newAsset[k])
		}
	}
	common.CreateResponse(c, common.SuccessCode, "ok")
}
