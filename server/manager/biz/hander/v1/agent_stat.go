package v1

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

//GetStatusByID get agent status by agent_id
//GET GetStatusByID/xxxxxxxx
func GetStatusByID(c *gin.Context) {
	agentID := c.Param("id")
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	var heartbeat map[string]interface{}
	err := collection.FindOne(context.Background(), bson.M{"agent_id": agentID}).Decode(&heartbeat)
	if err != nil {
		ylog.Errorf("GetAgentStat Mongodb ", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, heartbeat)
	return
}

//GetStatus get all agent status.
//GET /getStatus?page=1&page_size=100
func GetStatus(c *gin.Context) {
	var pageRequest common.PageRequest

	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetStatus", err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	modelPage, err := common.DBModelPaginate(
		collection,
		common.PageOption{Page: pageRequest.Page, PageSize: pageRequest.PageSize, Filter: bson.M{}},
		func(cursor *mongo.Cursor) (interface{}, error) {
			var item map[string]interface{}
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("GetStatus", err.Error())
				return nil, err
			}
			return item, nil
		})

	if err != nil {
		ylog.Errorf("GetStatus", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, modelPage)
}

//GetStatusByFilter get agent status by filter
//Example: (Post json is a common filter)
//	Post /getStatus/filter?page=1&page_size=100
//		{
//    		"filter": [
//        	{
//            	"key": "last_heartbeat_time",
//            	"rules": [
//         	       {
//         	           "operator": "$gt",
//           	         "value": 1614255379
//         	       }
//        	    ],
//       	     "condition": "$and"
//       	 }
//    		],
//    		"condition": "$and"
//		}
//which will return agents'status which match agent_id.last_heartbeat_time > 1614255379
func GetStatusByFilter(c *gin.Context) {
	var pageRequest common.PageRequest

	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("QueryStat", err.Error())
		return
	}

	filterQuery, err := common.BindFilterQuery(c)
	if err != nil {
		ylog.Errorf("QueryStat", err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)

	modelPage, err := common.DBModelPaginate(
		collection,
		common.PageOption{Page: pageRequest.Page, PageSize: pageRequest.PageSize, Filter: filterQuery.Transform()},
		func(cursor *mongo.Cursor) (interface{}, error) {
			var item map[string]interface{}
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("QueryStat", err.Error())
				return nil, err
			}
			return item, nil
		})

	if err != nil {
		ylog.Errorf("QueryStat", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, modelPage)
}
