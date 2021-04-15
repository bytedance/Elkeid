package v1

import (
	"context"
	"github.com/bytedance/Elkeid/server/manger/biz/common"
	"github.com/bytedance/Elkeid/server/manger/infra"
	"github.com/bytedance/Elkeid/server/manger/infra/def"
	"github.com/bytedance/Elkeid/server/manger/infra/ylog"
	"github.com/bytedance/Elkeid/server/manger/task"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

//更新对账任务数据
func UpdateSubTask(c *gin.Context) {
	var request []map[string]interface{}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("UpdateSubTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	for _, v := range request {
		task.SubTaskUpdateAsyncWrite(v)
	}
	common.CreateResponse(c, common.SuccessCode, nil)
}

func GetSubTaskByFilter(c *gin.Context) {
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetSubTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	filterQuery, err := common.BindFilterQuery(c)
	if err != nil {
		ylog.Errorf("GetSubTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)

	modelPage, err := common.DBModelPaginate(
		collection,
		common.PageOption{Page: pageRequest.Page, PageSize: pageRequest.PageSize, Filter: filterQuery.Transform()},
		func(cursor *mongo.Cursor) (interface{}, error) {
			var item map[string]interface{}
			err := cursor.Decode(&item)
			if err != nil {
				ylog.Errorf("GetSubTask", err.Error())
				return nil, err
			}
			return item, nil
		})

	if err != nil {
		ylog.Errorf("GetSubTask", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, modelPage)
}

func GetSubTaskByID(c *gin.Context) {
	taskID := c.Param("id")
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	cursor, err := collection.Find(context.Background(), bson.M{"task_id": taskID})
	if err != nil {
		ylog.Errorf("GetSubTaskByID", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	res := make([]interface{}, 0)
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		var subTask def.AgentSubTask
		err := cursor.Decode(&subTask)
		if err != nil {
			ylog.Errorf("GetSubTaskByID", err.Error())
			continue
		}
		res = append(res, subTask)
	}
	common.CreateResponse(c, common.SuccessCode, res)
}
