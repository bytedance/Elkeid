package v6

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	v1 "github.com/bytedance/Elkeid/server/manager/biz/hander/v1"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

type TaskDetail struct {
	TaskId         string `json:"task_id" bson:"task_id"`
	TaskName       string `json:"task_name" bson:"task_name"`
	TaskStatus     string `json:"task_status" bson:"task_status"`
	Action         string `json:"action" bson:"action"`
	TaskUser       string `json:"task_user" bson:"task_user"`
	Tag            string `json:"tag" bson:"tag"`
	IdCount        int    `json:"id_count" bson:"id_count"`
	SubTaskCreated int    `json:"sub_task_created" bson:"sub_task_created"`
	SubTaskFailed  int    `json:"sub_task_failed" bson:"sub_task_failed"`
	SubTaskSucceed int    `json:"sub_task_succeed" bson:"sub_task_succeed"`
	CreateTime     int64  `json:"create_time" bson:"create_time"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
}

type CreateTask struct {
	Action         string             `json:"action" bson:"action"`
	TaskName       string             `json:"task_name" bson:"task_name"`
	ModuleId       primitive.ObjectID `json:"module_id" bson:"_id"`
	GeneralHostReq `json:",omitempty,inline"`
}

// 获取任务列表
func GetTaskList(c *gin.Context) {
	type TaskRequest struct {
		TaskName   string   `json:"task_name,omitempty" bson:"task_name,omitempty"`
		TaskStatus []string `json:"task_status,omitempty" bson:"task_status,omitempty"`
		Action     []string `json:"action,omitempty" bson:"action,omitempty"`
		TaskUser   string   `json:"task_user,omitempty" bson:"task_user,omitempty"`
		Tag        string   `json:"tag,omitempty" bson:"tag,omitempty"`
	}

	// 绑定分页数据
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}
	pageRequest.OrderKey = "create_time"
	pageRequest.OrderValue = -1

	// 绑定任务筛选数据
	var taskRequest TaskRequest
	err = c.BindJSON(&taskRequest)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if taskRequest.TaskName != "" {
		searchFilter["task_name"] = MongoRegex{Regex: taskRequest.TaskName}
	}
	if len(taskRequest.TaskStatus) != 0 {
		searchFilter["task_status"] = MongoInside{Inside: taskRequest.TaskStatus}
	}
	if len(taskRequest.Action) != 0 {
		searchFilter["action"] = MongoInside{Inside: taskRequest.Action}
	}
	if taskRequest.TaskUser != "" {
		searchFilter["task_usr"] = taskRequest.TaskUser
	}
	if taskRequest.Tag != "" {
		searchFilter["tag"] = taskRequest.Tag
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	pageSearch := PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	var dataResponse []TaskDetail
	pageResponse, err := DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var taskReponse TaskDetail
			err := cursor.Decode(&taskReponse)
			if err != nil {
				ylog.Errorf("GetTaskList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, taskReponse)

			// 更新子任务状态
			var task v1.AgentConfigTaskAll
			cursor.Decode(&task)
			v1.ComputeSubTaskStat(&task)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 获取子任务列表
func GetSubTaskList(c *gin.Context) {
	type SubTaskRequest struct {
		TaskId   string   `json:"task_id" bson:"task_id"`
		Status   []string `json:"status,omitempty" bson:"status,omitempty"`
		Hostname string   `json:"hostname,omitempty" bson:"hostname,omitempty"`
	}
	type SubTaskDetail struct {
		TaskId     string `json:"task_id" bson:"task_id"`
		AgentId    string `json:"agent_id" bson:"agent_id"`
		Status     string `json:"status" bson:"status"`
		Hostname   string `json:"hostname" bson:"hostname"`
		UpdateTime int64  `json:"update_time" bson:"update_time"`
	}
	type subTaskName struct {
		AgentId  string `bson:"agent_id"`
		Hostname string `bson:"hostname"`
	}

	// 绑定分页数据
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetSubTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定任务筛选数据
	var subTaskRequest SubTaskRequest
	err = c.BindJSON(&subTaskRequest)
	if err != nil {
		ylog.Errorf("GetSubTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接子任务查询语句
	subTaskFilter := make(map[string]interface{})
	subTaskFilter["task_id"] = subTaskRequest.TaskId
	if len(subTaskRequest.Status) != 0 {
		subTaskFilter["status"] = MongoInside{Inside: subTaskRequest.Status}
	}

	// 拼接主机信息查询语句
	agentFilter := make(map[string]interface{})
	if subTaskRequest.Hostname != "" {
		agentFilter["hostname"] = MongoRegex{Regex: subTaskRequest.Hostname}
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	pageSearch := PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: nil, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo聚合查询
	var aggregateSearchList bson.A

	// 加入agent_vuln_info表的过滤条件
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": subTaskFilter})

	// 连表查询，查询vuln_info表的信息
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from":         infra.AgentHeartBeatCollection,
		"localField":   "agent_id",
		"foreignField": "agent_id",
		"as":           "inventory_docs",
	}})

	// 加入主机表查询的过滤条件
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{
		"inventory_docs": MongoElem{Value: agentFilter},
	}})

	// 聚合查询

	var dataResponse []SubTaskDetail
	pageResponse, err := DBAggregatePaginate(
		collection,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			v := struct {
				TaskId        string        `json:"task_id" bson:"task_id"`
				AgentId       string        `json:"agent_id" bson:"agent_id"`
				Status        string        `json:"status" bson:"status"`
				UpdateTime    int64         `json:"update_time" bson:"update_time"`
				InventoryDocs []subTaskName `json:"inventory_docs" bson:"inventory_docs"`
			}{}
			_ = cursor.Decode(&v)

			var subTaskInfo SubTaskDetail
			subTaskInfo.TaskId = v.TaskId
			subTaskInfo.AgentId = v.AgentId
			subTaskInfo.Status = v.Status
			subTaskInfo.UpdateTime = v.UpdateTime

			if len(v.InventoryDocs) > 0 {
				agentInfo := v.InventoryDocs[0]
				subTaskInfo.Hostname = agentInfo.Hostname
			}
			dataResponse = append(dataResponse, subTaskInfo)
			return nil
		},
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)

}

// 控制插件更新安装卸载
func ControlPlugin(c *gin.Context) {
	// 生成任务信息
	createTask := &CreateTask{}
	err := c.BindJSON(createTask)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 寻找对应插件
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
	res := collection.FindOne(c, bson.M{"_id": createTask.ModuleId})
	if res.Err() != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "can't find module")
		return
	}
	plugin := &AgentConfigMsg{}
	res.Decode(plugin)

	if plugin.Type == "archive" {
		plugin.Type = "tar.gz"
	}

	// 补全任务信息
	agentConfigTask := &v1.AgentConfigTask{}
	agentConfigTask.Action = createTask.Action
	agentConfigTask.TaskName = createTask.TaskName
	if createTask.Action == "plu_uninstall" {
		agentConfigTask.Data.Config = []AgentConfigMsg{
			{
				Name: plugin.Name,
			},
		}

	} else if createTask.Action == "plu_update" || createTask.Action == "plu_install" {
		agentConfigTask.Data.Config = []AgentConfigMsg{*plugin}
	} else {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "unknown action")
		return
	}

	// 生成任务下发主机列表
	filter := bson.M{}
	if len(createTask.IdList) != 0 {
		agentConfigTask.IDList = createTask.IdList
	} else {
		filter = createTask.GenerateFilter()
		collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		cur, err := collection.Find(c, filter, options.Find().SetProjection(bson.M{"agent_id": 1}))
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		defer cur.Close(c)
		idStruct := struct {
			AgentId string `json:"agent_id" bson:"agent_id"`
		}{}
		for cur.Next(c) {
			_ = cur.Decode(&idStruct)
			agentConfigTask.IDList = append(agentConfigTask.IDList, idStruct.AgentId)
		}
	}

	// 记录操作用户
	operateUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	agentConfigTask.TaskUser = operateUser.(string)

	// 下发任务
	tID, count, err := v1.CreateTask(agentConfigTask, "Agent_Config")
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

// 控制agent更新重启
func ControlAgent(c *gin.Context) {
	// 生成任务信息
	createTask := &CreateTask{}
	err := c.BindJSON(createTask)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 补全任务信息
	var tType = ""
	agentConfigTask := &v1.AgentConfigTask{}
	agentConfigTask.Action = createTask.Action
	agentConfigTask.TaskName = createTask.TaskName
	if createTask.Action == "agt_update" {
		tType = "Agent_Config"
		// 寻找对应agent模块
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
		res := collection.FindOne(c, bson.M{"_id": createTask.ModuleId})
		if res.Err() != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "can't find module")
			return
		}
		plugin := &AgentConfigMsg{}
		res.Decode(plugin)
		agentConfigTask.Data.Config = []AgentConfigMsg{*plugin}
	} else if createTask.Action == "agt_reboot" {
		tType = "Agent_Task"
		agentConfigTask.Data.Task = AgentTaskMsg{
			Name:     v1.TaskAgentName,
			DataType: v1.AgentRebootType,
		}
	} else {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "unknown action")
		return
	}

	// 生成任务下发主机列表
	filter := bson.M{}
	if len(createTask.IdList) != 0 {
		agentConfigTask.IDList = createTask.IdList
	} else {
		filter = createTask.GenerateFilter()
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		cur, err := collection.Find(c, filter, options.Find().SetProjection(bson.M{"agent_id": 1}))
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		defer cur.Close(c)
		idStruct := struct {
			AgentId string `json:"agent_id" bson:"agent_id"`
		}{}
		for cur.Next(c) {
			_ = cur.Decode(&idStruct)
			agentConfigTask.IDList = append(agentConfigTask.IDList, idStruct.AgentId)
		}
	}

	// 记录操作用户
	operateUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	agentConfigTask.TaskUser = operateUser.(string)

	// 下发任务
	tID, count, err := v1.CreateTask(agentConfigTask, tType)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})

}

// 获取不能下发任务的主机数量
func GetErrorHostNum(c *gin.Context) {
	// 生成任务信息
	reqeust := &GeneralHostReq{}
	err := c.BindJSON(reqeust)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 返回结构体
	type responseStruct struct {
		ErrorNum int64 `json:"error_num"`
		AllNum   int64 `json:"all_num"`
	}
	var response responseStruct

	// 生成任务下发主机列表
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	filter := bson.M{}
	if len(reqeust.IdList) > 0 {
		filter["agent_id"] = MongoInside{Inside: reqeust.IdList}
		response.AllNum = int64(len(reqeust.IdList))
	} else {
		filter = reqeust.GenerateFilter()
		num, err := collection.CountDocuments(c, filter)
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		response.AllNum = num
	}
	current := time.Now().Unix()
	filter["last_heartbeat_time"] = MongoGte{Value: current - 600}

	num, err := collection.CountDocuments(c, filter)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	response.ErrorNum = response.AllNum - num
	common.CreateResponse(c, common.SuccessCode, response)

}
