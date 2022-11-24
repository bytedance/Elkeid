package v1

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/distribute/job"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type AgentTaskControl struct {
	TaskID         string  `json:"task_id" binding:"required" bson:"task_id"`
	Action         string  `json:"action" binding:"required" bson:"action"`
	RollingPercent float64 `json:"rolling_percent" binding:"required" bson:"rolling_percent"`
	Concurrence    int     `json:"concurrence" binding:"required" bson:"concurrence"`
}

type AgentDelRequest struct {
	Tag    string   `json:"tag" bson:"tag"`
	IDList []string `json:"id_list" bson:"id_list"`
	Data   []string `json:"data" binding:"required" bson:"data"`
}

// ControlAgentTask Post task to Agent:
//
//	if it is config, modify db at the same time.
//	if it is task, write the task to db(subtask) for reconciliation.
func ControlAgentTask(c *gin.Context) {
	var request AgentTaskControl
	//Check request field.
	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	switch request.Action {
	case "cancel":
		err = atask.CancelTask(request.TaskID)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		common.CreateResponse(c, common.SuccessCode, bson.M{"taskID": request.TaskID})
	case "run":
		if request.RollingPercent <= 0 || request.RollingPercent > 1 {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "RollingPercent must between 0 and 1")
			return
		}
		if request.Concurrence <= 0 || request.Concurrence >= 1000 {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "Concurrence must between 0 and 1000")
			return
		}

		jID, count, err := atask.RunTask(request.TaskID, request.RollingPercent, 0, request.Concurrence)
		if err != nil {
			common.CreateResponse(c, common.UnknownErrorCode, err.Error())
			return
		}

		common.CreateResponse(c, common.SuccessCode, bson.M{"taskID": request.TaskID, "jobID": jID, "id_count": count})
	default:
		common.CreateResponse(c, common.ParamInvalidErrorCode, "action only support cancel|run")
	}
}

// QuickTaskTask 不对账
func QuickTaskTask(c *gin.Context) {
	request := &AgentQuickTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("QuickTaskTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	needToken := false
	if c.Query("token") == "true" {
		needToken = true
	}

	timeout, err := strconv.Atoi(c.Query("timeout"))
	if err != nil {
		timeout = 0
	}

	taskID, err := atask.SendFastTask(request.AgentID, &request.Command.Task, needToken, int64(timeout), nil)
	if err != nil {
		ylog.Errorf("SendFastTask", "agentID %s, error %s", request.AgentID, err.Error())
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, taskID)
	return
}

func CreateCtrlTask(c *gin.Context) {
	request := &atask.AgentTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	tID, count, err := atask.CreateCtrlTask(request)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

func CreateConfTask(c *gin.Context) {
	request := &atask.AgentTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	tID, count, err := atask.CreateConfTask(request)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

func CreateTaskTask(c *gin.Context) {
	request := &atask.AgentTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	tID, count, err := atask.CreateTaskTask(request)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

func CreateDelConfTask(c *gin.Context) {
	request := &AgentDelRequest{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	task := &atask.AgentTask{
		Data: ConfigRequest{
			AgentCtrl: 0,
			Config:    make([]AgentConfigMsg, len(request.Data)),
		},
		Tag:    request.Tag,
		IDList: request.IDList,
	}

	for k, v := range request.Data {
		task.Data.Config[k] = AgentConfigMsg{
			Name: v,
		}
	}

	tID, count, err := atask.CreateConfTask(task)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

// GetTaskByID return task task_id.
func GetTaskByID(c *gin.Context) {
	taskID := c.Param("id")
	task, err := atask.GetTaskByID(taskID)
	if err != nil {
		ylog.Errorf("GetTaskByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, task)
	return
}

func GetTaskByFilter(c *gin.Context) {
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetTaskByFilter", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	filterQuery, err := common.BindFilterQuery(c)
	if err != nil {
		ylog.Errorf("GetTaskByFilter", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	pageOption := common.PageOption{Page: pageRequest.Page, PageSize: pageRequest.PageSize, Filter: filterQuery.Transform(), Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageOption.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	modelPage, err := common.DBModelPaginate(
		collection,
		pageOption,
		func(cursor *mongo.Cursor) (interface{}, error) {
			var task atask.AgentTask
			err := cursor.Decode(&task)
			if err != nil {
				ylog.Errorf("GetTaskByFilter", err.Error())
				return nil, err
			}
			task.ToDoList = []string{}
			return task, nil
		})

	if err != nil {
		ylog.Errorf("GetTaskByFilter", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, modelPage)
}

// GetJobByID return agent config by agent_id.
func GetJobByID(c *gin.Context) {
	showRes := false
	jID := c.Param("id")
	if c.Query("result") == "true" {
		showRes = true
	}
	jStat := job.GetStat(jID)
	if showRes {
		jRes := job.GetResult(jID)
		common.CreateResponse(c, common.SuccessCode, bson.M{"info": jStat["info"], "stat": jStat["stat"], "res": jRes})
	} else {
		common.CreateResponse(c, common.SuccessCode, bson.M{"info": jStat["info"], "stat": jStat["stat"], "res": nil})
	}

}

// ControlAgentTaskByNum 按照机器数量控制任务
func ControlAgentTaskByNum(c *gin.Context) {
	type AgentTaskControl struct {
		TaskID      string `json:"task_id" binding:"required" bson:"task_id"`
		Action      string `json:"action" binding:"required" bson:"action"`
		RunNumber   int    `json:"run_number" binding:"required" bson:"run_number"`
		Concurrence int    `json:"concurrence" binding:"required" bson:"concurrence"`
	}
	var request AgentTaskControl
	//Check request field.
	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	switch request.Action {
	case "cancel":
		_, err = taskCollection.UpdateOne(context.Background(), bson.M{"task_id": request.TaskID},
			bson.M{"$set": bson.M{"update_time": time.Now().Unix(), "task_status": atask.TaskStatusStopped, "inner_status": atask.TaskStatusStopped}})
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		common.CreateResponse(c, common.SuccessCode, bson.M{"taskID": request.TaskID})
	case "run":
		if request.RunNumber <= 0 {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "RollingPercent must between 0 and 1")
			return
		}
		if request.Concurrence <= 0 || request.Concurrence >= 1000 {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "Concurrence must between 0 and 1000")
			return
		}

		jID, count, err := atask.RunTask(request.TaskID, 0, request.RunNumber, request.Concurrence)
		if err != nil {
			common.CreateResponse(c, common.UnknownErrorCode, err.Error())
			return
		}

		common.CreateResponse(c, common.SuccessCode, bson.M{"taskID": request.TaskID, "jobID": jID, "id_count": count})
	default:
		common.CreateResponse(c, common.ParamInvalidErrorCode, "action only support cancel|run")
	}
}
