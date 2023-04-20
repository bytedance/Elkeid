package v6

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
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

type CreateFileScanTaskRequest struct {
	Action         string `json:"action" bson:"action"`
	TaskName       string `json:"task_name" bson:"task_name"`
	GeneralHostReq `json:",omitempty,inline" bson:",omitempty,inline"`
	FilePath       string `json:"file_path,omitempty" bson:"file_path,omitempty"`
	CpuIdle        string `json:"cpu_idle,omitempty" bson:"cpu_idle,omitempty"`
	Timeout        string `json:"timeout,omitempty" bson:"timeout,omitempty"`
}

type CreateTaskResponse struct {
	TaskId    string `json:"task_id" bson:"task_id"`
	TaskCount int    `json:"count" bson:"count"`
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
	var pageRequest common.PageRequest
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
		searchFilter["task_name"] = common.MongoRegex{Regex: taskRequest.TaskName}
	}
	if len(taskRequest.TaskStatus) != 0 {
		searchFilter["task_status"] = common.MongoInside{Inside: taskRequest.TaskStatus}
	}
	if len(taskRequest.Action) != 0 {
		searchFilter["action"] = common.MongoInside{Inside: taskRequest.Action}
	} else {
		var taskActions = [2]string{"reboot_agent", "sync_config"}
		searchFilter["action"] = common.MongoInside{Inside: taskActions}
	}
	if taskRequest.TaskUser != "" {
		searchFilter["task_usr"] = taskRequest.TaskUser
	}
	if taskRequest.Tag != "" {
		searchFilter["tag"] = taskRequest.Tag
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	var dataResponse []TaskDetail
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var task atask.AgentTask
			err = cursor.Decode(&task)
			if err != nil {
				ylog.Errorf("GetTaskList", err.Error())
				return err
			}
			if task.DistributedCount != 0 && task.DistributedCount == (task.SubTaskFailed+task.SubTaskSucceed) {
				task.TaskStatus = atask.TaskStatusFinished
			}

			item := TaskDetail{
				TaskId:         task.TaskID,
				TaskName:       task.TaskName,
				TaskStatus:     task.TaskStatus,
				Action:         task.Action,
				TaskUser:       task.TaskUser,
				Tag:            task.Tag,
				IdCount:        int(task.IDCount),
				SubTaskCreated: task.SubTaskCreated,
				SubTaskFailed:  task.SubTaskFailed,
				SubTaskSucceed: task.SubTaskSucceed,
				CreateTime:     task.CreateTime,
				UpdateTime:     task.UpdateTime,
			}
			dataResponse = append(dataResponse, item)
			return nil
		},
		options.Find().SetProjection(bson.M{
			"id_list":   0,
			"todo_list": 0,
		}),
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
	var pageRequest common.PageRequest
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
		subTaskFilter["status"] = common.MongoInside{Inside: subTaskRequest.Status}
	}

	// 拼接主机信息查询语句
	agentFilter := make(map[string]interface{})
	if subTaskRequest.Hostname != "" {
		agentFilter["hostname"] = common.MongoRegex{Regex: subTaskRequest.Hostname}
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: nil, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo聚合查询
	var aggregateSearchList bson.A

	// 加入agent_vuln_info表的过滤条件
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": subTaskFilter})

	// 连表查询，查询心跳表的信息
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from":         infra.AgentHeartBeatCollection,
		"localField":   "agent_id",
		"foreignField": "agent_id",
		"as":           "inventory_docs",
	}})

	// 加入主机表查询的过滤条件
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{
		"inventory_docs": common.MongoElem{Value: agentFilter},
	}})

	// 聚合查询

	var dataResponse []SubTaskDetail
	pageResponse, err := common.DBAggregatePaginate(
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
	agentConfigTask := &atask.AgentTask{}
	agentConfigTask.Action = createTask.Action
	agentConfigTask.TaskName = createTask.TaskName
	if createTask.Action == "agt_update" {
		tType = atask.TypeAgentConfig
		// 寻找对应agent模块
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentConfigTemplate)
		res := collection.FindOne(c, bson.M{"_id": createTask.ModuleId})
		if res.Err() != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "can't find module")
			return
		}
		plugin := &AgentConfigMsg{}
		err = res.Decode(plugin)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		agentConfigTask.Data.Config = []AgentConfigMsg{*plugin}
	} else if createTask.Action == "agt_reboot" {
		tType = atask.TypeAgentTask
		agentConfigTask.Data.Task = AgentTaskMsg{
			Name:     infra.AgentName,
			DataType: atask.AgentRebootType,
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
		defer func() {
			_ = cur.Close(c)
		}()
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
	tID, count, err := atask.CreateTask(agentConfigTask, tType)
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
	if task.DistributedCount != 0 && task.DistributedCount == (task.SubTaskFailed+task.SubTaskSucceed) {
		task.TaskStatus = atask.TaskStatusFinished
	}
	common.CreateResponse(c, common.SuccessCode, task)
	return
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
		filter["agent_id"] = common.MongoInside{Inside: reqeust.IdList}
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
	filter["last_heartbeat_time"] = bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}

	num, err := collection.CountDocuments(c, filter)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	response.ErrorNum = response.AllNum - num
	common.CreateResponse(c, common.SuccessCode, response)

}

type CreateSyncConfigTaskReqBody struct {
	TaskName       string `json:"task_name" bson:"task_name" binding:"required"`
	GeneralHostReq `json:",omitempty,inline"`
}

func CreateSyncConfigTask(c *gin.Context) {
	body := &CreateSyncConfigTaskReqBody{}
	err := c.Bind(&body)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	ylog.Infof("[CreateSyncConfigTask]", "receive request body: %+v", body)
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.ComponentPolicyCollection)
	cursor, err := coll.Find(c, bson.M{"type": "release"})
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	var policies []Policy
	err = cursor.All(c, &policies)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	ylog.Infof("[CreateSyncConfigTask]", "load policy successfully")
	coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	filter := body.GenerateFilter()
	taskID := fmt.Sprintf(`%d%s`, time.Now().UnixNano(), infra.RandStringBytes(6))
	cursor, err = coll.Aggregate(c, bson.A{
		bson.M{
			"$match": filter,
		},
		bson.M{
			"$project": bson.M{
				"_id":                0,
				"agent_id":           1,
				"platform_family":    1,
				"kernel_version":     1,
				"arch":               1,
				"tags":               1,
				"task_id":            taskID,
				"task_data.agent_id": "$agent_id",
			},
		},
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	// write subtask
	coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection, options.Collection().SetReadPreference(readpref.Primary()))
	var buf []interface{}
	count := int64(0)
	for cursor.Next(c) {
		if len(buf) > 200 {
			_, e := coll.InsertMany(c, buf)
			if e != nil {
				common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
				return
			} else {
				atomic.AddInt64(&count, int64(len(buf)))
			}
			ylog.Infof("[CreateSyncConfigTask]", "write subtask: %v", atomic.LoadInt64(&count))
			buf = buf[:0]
		}
		doc := bson.M{}
		err := cursor.Decode(&doc)
		if err != nil {
			continue
		}
		doc["token"] = atask.GenerateToken()
		buf = append(buf, doc)
	}
	if cursor.Err() != nil {
		err = cursor.Err()
	}
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	ylog.Infof("[CreateSyncConfigTask]", "bulk write done: %v", atomic.LoadInt64(&count))
	if len(buf) != 0 {
		_, err = coll.InsertMany(c, buf)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		atomic.AddInt64(&count, int64(len(buf)))
	}
	ylog.Infof("[CreateSyncConfigTask]", "write subtask: %v", atomic.LoadInt64(&count))
	// add config
	cursor, err = coll.Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"task_id": taskID,
			}},
		bson.M{
			"$group": bson.M{
				"_id": bson.M{
					"arch":            "$arch",
					"platform_family": "$platform_family",
				},
			}},
		bson.M{"$project": bson.M{
			"_id":             0,
			"arch":            "$_id.arch",
			"platform_family": "$_id.platform_family",
		}},
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var infos []*ContextInfo
	err = cursor.All(c, &infos)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	for _, info := range infos {
		var config []*ComponentInstance
		for _, policy := range policies {
			if c, err := policy.GetIntance(info); err == nil {
				config = append(config, c)
			}
		}
		_, err = coll.UpdateMany(c,
			bson.M{
				"task_id":         taskID,
				"platform_family": info.PlatformFamily,
				"arch":            info.Arch,
			},
			bson.M{
				"$set": bson.M{
					"task_data.command.config": config,
				},
			},
		)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}
	ylog.Infof("[CreateSyncConfigTask]", "add config successfully")
	// block config
	for _, policy := range policies {
		var filter []bson.M
		for _, rule := range policy.Rules {
			filter = append(filter, rule.ToBson())
		}
		if len(filter) != 0 {
			_, err := coll.UpdateMany(c,
				bson.M{
					"task_id": taskID,
					"$or":     filter,
				},
				bson.M{
					"$pull": bson.M{
						"task_data.command.config": bson.M{
							"name": policy.Component.Name,
						}},
				})
			if err != nil {
				common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
				return
			}
		}
	}
	ylog.Infof("[CreateSyncConfigTask]", "block config successfully")
	// add task
	cursor, err = coll.Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"task_id": taskID,
			}},
		bson.M{
			"$project": bson.M{
				"agent_id": 1,
				"_id":      0,
			}}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var ts []struct {
		AgentID string `bson:"agent_id"`
	}
	err = cursor.All(c, &ts)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var todoList []string
	for _, t := range ts {
		todoList = append(todoList, t.AgentID)
	}
	if count != int64(len(todoList)) {
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("todolist num is not equal to count: %v vs %v", len(todoList), count))
		return
	}
	_, err = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection).
		InsertOne(c, bson.M{
			"task_id":     taskID,
			"task_name":   body.TaskName,
			"action":      "sync_config",
			"task_type":   "Agent_Config_v2",
			"task_status": "created",
			"task_user":   c.GetString("user"),
			"id_count":    count,
			"create_time": time.Now().Unix(),
			"todo_list":   todoList,
		})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		common.CreateResponse(c, common.SuccessCode, taskID)
	}
}

type CreateRebootAgentTaskReqBody struct {
	TaskName       string `json:"task_name" bson:"task_name" binding:"required"`
	GeneralHostReq `json:",omitempty,inline"`
}

func CreateRebootAgentTask(c *gin.Context) {
	body := CreateRebootAgentTaskReqBody{}
	err := c.BindJSON(&body)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	// 补全任务信息
	agentConfigTask := &atask.AgentTask{}
	agentConfigTask.Action = "reboot_agent"
	agentConfigTask.TaskName = body.TaskName
	agentConfigTask.TaskType = "Agent_Task"
	agentConfigTask.Data.Task = AgentTaskMsg{
		Name:     infra.AgentName,
		DataType: atask.AgentRebootType,
	}
	// 生成任务下发主机列表
	if len(body.IdList) != 0 {
		agentConfigTask.IDList = body.IdList
	} else {
		filter := body.GenerateFilter()
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		cur, err := collection.Find(c, filter, options.Find().SetProjection(bson.M{"agent_id": 1}))
		if err != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
		defer func() {
			_ = cur.Close(c)
		}()
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
	tID, count, err := atask.CreateTask(agentConfigTask, agentConfigTask.TaskType)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})

}
