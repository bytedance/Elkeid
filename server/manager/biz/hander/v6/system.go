package v6

import (
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	dbtask "github.com/bytedance/Elkeid/server/manager/task"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

func InsertAlert(c *gin.Context) {
	var newAlert map[string]interface{}
	err := c.BindJSON(&newAlert)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	newAlert["leader_time"] = time.Now().Unix()
	dbtask.HubSystemAlertAsyncWrite(newAlert)
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func DescribeAlerts(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}

	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}

	data := make([]map[string]interface{}, 0, pq.PageSize)
	presp, err := DBSearchPaginate(c, preq, func(c *mongo.Cursor) error {
		item := map[string]interface{}{}
		err := c.Decode(&item)
		if err != nil {
			ylog.Errorf("DescribeAlerts", err.Error())
			return err
		}
		data = append(data, item)
		return nil
	})

	if err != nil {
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}
