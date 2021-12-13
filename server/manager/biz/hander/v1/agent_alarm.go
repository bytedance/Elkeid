package v1

import (
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	dbtask "github.com/bytedance/Elkeid/server/manager/task"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewAlarm(c *gin.Context) {
	var newAlarm map[string]interface{}
	err := c.BindJSON(&newAlarm)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	//0-->未处理
	newAlarm["__alarm_status"] = 0
	newAlarm["__update_time"] = time.Now().Unix()
	newAlarm["__insert_time"] = time.Now().Unix()
	newAlarm["__checked"] = false
	newAlarm["__hit_wl"] = false

	dbtask.HubAlarmAsyncWrite(newAlarm)
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func QueryAlarms(c *gin.Context) {
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	filterQuery, err := common.BindFilterQuery(c)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	pageOption := common.PageOption{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: bson.M{"$and": bson.A{filterQuery.Transform(), bson.M{"__checked": true, "__hit_wl": false}}}, Sorter: nil}

	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageOption.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}
	modelPage, err := common.DBModelPaginate(
		collection,
		pageOption,
		func(cursor *mongo.Cursor) (interface{}, error) {
			var item map[string]interface{}
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("QueryAlarms", err.Error())
				return nil, err
			}
			return item, nil
		})

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, modelPage)
}

type AlarmUpdater struct {
	ID          string `json:"id" bson:"id"`
	AlarmStatus int    `json:"alarm_status" bson:"alarm_status"`
}

type AlarmResp struct {
	ID   string `json:"id" bson:"id"`
	Code int    `json:"code" bson:"code"`
	Msg  string `json:"msg" bson:"msg"`
}

func UpdateAlarms(c *gin.Context) {
	alarms := make([]AlarmUpdater, 0)
	err := c.BindJSON(&alarms)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	res := make([]AlarmResp, 0, len(alarms))
	writes := make([]mongo.WriteModel, 0, len(alarms))
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)

	for _, v := range alarms {
		tmp := AlarmResp{
			ID:   v.ID,
			Code: 0,
			Msg:  "ok",
		}

		objId, err := primitive.ObjectIDFromHex(v.ID)
		if err != nil {
			tmp.Code = 1
			tmp.Msg = err.Error()
		} else {
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"_id": objId}).SetUpdate(bson.M{"$set": bson.M{"__alarm_status": v.AlarmStatus, "__update_time": time.Now().Unix()}}).SetUpsert(false)
			writes = append(writes, model)
		}
		res = append(res, tmp)
	}
	_, err = col.BulkWrite(c, writes, writeOption)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, res)
}
