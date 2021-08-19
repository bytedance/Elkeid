package v1

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"strings"
)

type TagRequest struct {
	Tag    string   `json:"tag" binding:"required"`
	IPv4   []string `json:"ipv4_list"`
	IPv6   []string `json:"ipv6_list"`
	Agents []string `json:"id_list"`
}

type LoadTagReq struct {
	IDList []string `json:"id_list" binding:"required"`
}

//AddTags add tags by agent_id/ipv4/ipv6
func AddTags(c *gin.Context) {
	var tagRequest TagRequest

	err := c.BindJSON(&tagRequest)
	if err != nil {
		ylog.Errorf("AddTags", err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)

	for _, ip := range tagRequest.IPv4 {
		_, err = collection.UpdateMany(
			context.Background(),
			bson.M{
				"$or": []bson.M{
					{"intranet_ipv4": ip}, {"extranet_ipv4": ip},
				},
			},
			bson.M{
				"$addToSet": bson.M{"tags": tagRequest.Tag},
			})

		if err != nil {
			ylog.Errorf("AddTags", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	for _, ip := range tagRequest.IPv6 {
		_, err = collection.UpdateMany(
			context.Background(),
			bson.M{
				"$or": []bson.M{
					{"extranet_ipv6": ip}, {"intranet_ipv6": ip},
				},
			},
			bson.M{
				"$addToSet": bson.M{"tags": tagRequest.Tag},
			})

		if err != nil {
			ylog.Errorf("AddTags", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	for _, id := range tagRequest.Agents {
		_, err = collection.UpdateMany(
			context.Background(),
			bson.M{"agent_id": id},
			bson.M{
				"$addToSet": bson.M{"tags": tagRequest.Tag},
			})

		if err != nil {
			ylog.Errorf("AddTags", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	common.CreateResponse(c, common.SuccessCode, nil)
}

//AddTagsByFilter add tags by filter.
//Example: (Post json is a common filter)
//	Post /addTags/filter?tag=test
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
//which will add add test to all agent_id.last_heartbeat_time > 1614255379
func AddTagsByFilter(c *gin.Context) {
	tag, ok := c.GetQuery("tag")
	if !ok {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "The query parameter tag must be set.")
		return
	}

	filter, err := common.BindFilterQuery(c)
	if err != nil {
		ylog.Errorf("AddTagsByFilter", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	result, err := collection.UpdateMany(
		context.Background(),
		filter.Transform(),
		bson.M{
			"$addToSet": bson.M{"tags": tag},
		})

	if err != nil {
		ylog.Errorf("AddTagsByFilter", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, gin.H{"count": result.ModifiedCount})
}

//RemoveTags remove tag by agent_id/ipv4/ipv6
func RemoveTags(c *gin.Context) {
	var tagRequest TagRequest

	err := c.BindJSON(&tagRequest)
	if err != nil {
		ylog.Errorf("AddTags", err.Error())
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)

	for _, ip := range tagRequest.IPv4 {
		_, err = collection.UpdateMany(
			context.Background(),
			bson.M{
				"$or": []bson.M{
					{"intranet_ipv4": ip}, {"extranet_ipv4": ip},
				},
			},
			bson.M{
				"$pull": bson.M{"tags": tagRequest.Tag},
			})

		if err != nil {
			ylog.Errorf("RemoveTags", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	for _, ip := range tagRequest.IPv6 {
		_, err = collection.UpdateMany(
			context.Background(),
			bson.M{
				"$or": []bson.M{
					{"extranet_ipv6": ip}, {"intranet_ipv6": ip},
				},
			},
			bson.M{
				"$pull": bson.M{"tags": tagRequest.Tag},
			})

		if err != nil {
			ylog.Errorf("RemoveTags", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	for _, id := range tagRequest.Agents {
		_, err = collection.UpdateMany(
			context.Background(),
			bson.M{"agent_id": id},
			bson.M{
				"$pull": bson.M{"tags": tagRequest.Tag},
			})

		if err != nil {
			ylog.Errorf("RemoveTags", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	common.CreateResponse(c, common.SuccessCode, nil)
}

//GetTags load all tags.
func GetTags(c *gin.Context) {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	data, err := collection.Distinct(context.Background(), "tags", bson.M{})

	if err != nil {
		ylog.Errorf("GetTags", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, data)
}

//GetTagsByID query tag by agent_id
func GetTagsByID(c *gin.Context) {
	var tagRequest LoadTagReq
	err := c.BindJSON(&tagRequest)
	if err != nil {
		ylog.Errorf("GetTagsByID", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := agentCollection.Find(context.Background(),
		bson.M{"agent_id": bson.M{"$in": tagRequest.IDList}})
	if err != nil {
		ylog.Errorf("GetTagsByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	res := map[string]string{}
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		var heartbeat AgentHBInfo
		err := cursor.Decode(&heartbeat)
		if err != nil {
			ylog.Errorf("GetTagsByID", err.Error())
			continue
		}
		res[heartbeat.AgentId] = strings.Join(heartbeat.Tags, ",")
	}
	common.CreateResponse(c, common.SuccessCode, res)
}
