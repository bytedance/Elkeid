package v1

import (
	"context"
	"github.com/bytedance/Elkeid/server/manger/biz/common"
	"github.com/bytedance/Elkeid/server/manger/infra"
	"github.com/bytedance/Elkeid/server/manger/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

const (
	AgentOnlineDelay = 20 * time.Minute
)

type StateFilterRequest struct {
	Filter string `form:"filter,default=all" binding:"required,oneof=all online offline"`
}

type StatisticModel struct {
	Data          []map[string]interface{} `json:"data" bson:"data"`
	HeartBeatFrom string                   `json:"heartbeat_time_from" bson:"heartbeat_time_from"`
	HeartBeatEnd  string                   `json:"heartbeat_end" bson:"heartbeat_end"`
}

func GetVersion(c *gin.Context) {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	hbFrom := time.Now().Add(-AgentOnlineDelay)
	onlineFilter := bson.M{"last_heartbeat_time": bson.M{"$gte": hbFrom.Unix()}}
	pline := []bson.M{
		{"$match": onlineFilter},
		{"$group": bson.M{"_id": "$version", "count": bson.M{"$sum": 1}}},
		{"$project": bson.M{"Version": "$_id", "count": 1, "_id": 0}},
	}
	cur, err := collection.Aggregate(context.Background(), pline)
	if err != nil {
		ylog.Errorf("GetStatistic", "collection.Aggregate Error dbname %s, err: %v", infra.AgentHeartBeatCollection, err)
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var res []map[string]interface{}
	err = cur.All(context.Background(), &res)
	if err != nil {
		ylog.Errorf("GetStatistic", "collection.Aggregate Error dbname %s, err: %v", infra.AgentHeartBeatCollection, err)
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var state = StatisticModel{
		Data:          res,
		HeartBeatFrom: hbFrom.Format("2006-01-02 15:04:05"),
		HeartBeatEnd:  time.Now().Format("2006-01-02 15:04:05"),
	}
	common.CreateResponse(c, common.SuccessCode, state)
}

// get count
func GetCount(c *gin.Context) {
	var stateFilterPage StateFilterRequest
	err := c.BindQuery(&stateFilterPage)
	if err != nil {
		ylog.Errorf("GetCount", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	hbFrom := time.Unix(0, 0)
	hbEnd := time.Now().Add(AgentOnlineDelay)
	if stateFilterPage.Filter == "online" {
		hbFrom = time.Now().Add(-AgentOnlineDelay)
	} else if stateFilterPage.Filter == "offline" {
		hbEnd = time.Now().Add(-AgentOnlineDelay)
	}

	filter := bson.M{"last_heartbeat_time": bson.M{"$gte": hbFrom.Unix(), "$lt": hbEnd.Unix()}}
	count, err := collection.CountDocuments(context.Background(), filter)
	if err != nil {
		ylog.Errorf("GetCount", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, gin.H{"count": count})
}
