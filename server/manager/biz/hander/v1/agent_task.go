package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/distribute/job"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/task"
	"github.com/gin-gonic/gin"
	"github.com/levigross/grequests"
	"github.com/rs/xid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//for response
type AgentConfigMsgAll struct {
	Name        string   `json:"name" binding:"required" bson:"name"`
	Type        string   `json:"type,omitempty" bson:"type"`
	Signature   string   `json:"signature" bson:"signature"`
	Version     string   `json:"version" bson:"version"`
	SHA256      string   `json:"sha256" bson:"sha256"`
	DownloadURL []string `json:"download_url" bson:"download_url"`
	Detail      string   `json:"detail" bson:"detail"`
}

type AgentTaskMsgAll struct {
	Name     string `json:"name" bson:"name"`
	Data     string `json:"data" bson:"data"`
	Token    string `json:"token" bson:"token"`
	DataType int32  `json:"data_type" bson:"data_type"`
}

type ConfigRequestAll struct {
	AgentCtrl int                 `json:"agent_ctrl" bson:"agent_ctrl"`
	Task      AgentTaskMsgAll     `json:"task" bson:"task"`
	Config    []AgentConfigMsgAll `json:"config" bson:"config"`
}

type AgentConfigTaskAll struct {
	Tag    string           `json:"tag" bson:"tag"`
	IDList []string         `json:"id_list" bson:"id_list"`
	Data   ConfigRequestAll `json:"data" binding:"required" bson:"data"`

	TaskName         string   `json:"task_name" bson:"task_name"`
	TaskID           string   `json:"task_id" bson:"task_id"`
	TaskType         string   `json:"task_type" bson:"task_type"`
	InnerStatus      string   `json:"inner_status" bson:"inner_status"` //记录下发状态
	TaskStatus       string   `json:"task_status" bson:"task_status"`   //记录任务状态
	ToDoList         []string `json:"todo_list" bson:"todo_list"`
	IDCount          float64  `json:"id_count" bson:"id_count"`
	DistributedCount int      `json:"distributed_count" bson:"distributed_count"` //下发总数，可能未执行完成
	JobList          []string `json:"job_list" bson:"job_list"`
	Action           string   `json:"action" bson:"action"`
	TaskUser         string   `json:"task_user" bson:"task_user"`

	SubTaskCreated int `json:"sub_task_created" bson:"sub_task_created"`
	SubTaskRunning int `json:"sub_task_running" bson:"sub_task_running"`
	SubTaskFailed  int `json:"sub_task_failed" bson:"sub_task_failed"`
	SubTaskSucceed int `json:"sub_task_succeed" bson:"sub_task_succeed"`

	CreateTime int64 `json:"create_time" bson:"create_time" bson:"create_time"`
	UpdateTime int64 `json:"update_time" bson:"update_time" bson:"update_time"`
}

type AgentDelRequest struct {
	Tag    string   `json:"tag" bson:"tag"`
	IDList []string `json:"id_list" bson:"id_list"`
	Data   []string `json:"data" binding:"required" bson:"data"`
}

type AgentConfigTask struct {
	Tag    string              `json:"tag" bson:"tag"`
	IDList []string            `json:"id_list" bson:"id_list"`
	Filter *common.FilterQuery `json:"filter" bson:"filter"`
	Data   ConfigRequest       `json:"data" binding:"required" bson:"data"`

	TaskName         string   `json:"task_name" bson:"task_name"`
	TaskID           string   `json:"task_id" bson:"task_id"`
	TaskType         string   `json:"task_type" bson:"task_type"`
	InnerStatus      string   `json:"inner_status" bson:"inner_status"` //记录下发状态
	TaskStatus       string   `json:"task_status" bson:"task_status"`   //记录任务状态
	ToDoList         []string `json:"todo_list" bson:"todo_list"`
	IDCount          float64  `json:"id_count" bson:"id_count"`
	DistributedCount int      `json:"distributed_count" bson:"distributed_count"` //下发总数，可能未执行完成
	JobList          []string `json:"job_list" bson:"job_list"`
	Action           string   `json:"action" bson:"action"`
	TaskUser         string   `json:"task_user" bson:"task_user"`

	//count from subTask
	SubTaskCreated int `json:"sub_task_created" bson:"sub_task_created"`
	SubTaskRunning int `json:"sub_task_running" bson:"sub_task_running"`
	SubTaskFailed  int `json:"sub_task_failed" bson:"sub_task_failed"`
	SubTaskSucceed int `json:"sub_task_succeed" bson:"sub_task_succeed"`

	CreateTime int64 `json:"create_time" bson:"create_time" bson:"create_time"`
	UpdateTime int64 `json:"update_time" bson:"update_time" bson:"update_time"`
}

type AgentTaskControl struct {
	TaskID         string  `json:"task_id" binding:"required" bson:"task_id"`
	Action         string  `json:"action" binding:"required" bson:"action"`
	RollingPercent float64 `json:"rolling_percent" binding:"required" bson:"rolling_percent"`
	Concurrence    int     `json:"concurrence" binding:"required" bson:"concurrence"`
}

type AgentJobParam struct {
	ConfigTask *AgentConfigTask
	TODOList   []string
	TaskID     string
	JobID      string
}

type SubTaskCount struct {
	ID    string `json:"_id" bson:"_id"`
	Count int    `json:"count" bson:"count"`
}

var AgentTaskTypeList = []string{"config", "task", "ctrl"}

const AgentJobTimeOut = 30 * 60 * 60 //30 minutes
const (
	TaskStatusCreated = "created" //未执行
	TaskStatusRunning = "running" //执行中

	//only for subtask_status
	TaskStatusFail    = "failed"
	TaskStatusSuccess = "succeed"

	//only for task_status && inner_status
	TaskStatusFinished = "finished"
	TaskStatusStopped  = "cancelled"
	TaskAgentName      = "mongoosev3-agent"
	AgentRebootType    = 1060
)

func init() {
	job.AJF.Register("Agent_Config", agentControlDistribute, agentControlDo, nil)
	job.AJF.Register("Agent_Ctrl", agentControlDistribute, agentControlDo, nil)
	job.AJF.Register("Agent_Task", agentControlDistribute, agentControlDo, nil)
}

func agentControlDistribute(k, v interface{}) (interface{}, error) {
	var (
		name          = k.(string)
		jobParam      = v.(AgentJobParam)
		jobs          = make([]job.JobArgs, 0)
		defaultConfig []AgentConfigMsg
	)
	//Load default policy from db.
	if name == "Agent_Config" {
		defaultConfig = getDefaultConfig()
	}

	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := agentCollection.Find(context.Background(),
		bson.M{"agent_id": bson.M{"$in": jobParam.TODOList}})
	if err != nil {
		ylog.Errorf("agentTaskDistribute", err.Error())
		return nil, err
	}

	agentIDMap := make(map[string]bool, 2000)
	defer cursor.Close(context.Background())
	for cursor.Next(context.Background()) {
		var hb AgentHBInfo
		err := cursor.Decode(&hb)
		if err != nil {
			ylog.Errorf("agentTaskDistribute", err.Error())
			continue
		}

		//Data update and query at the same time will cause duplicate data to be returned. Ensure that the data is not duplicated
		if _, ok := agentIDMap[hb.AgentId]; ok {
			continue
		} else {
			agentIDMap[hb.AgentId] = true
		}

		var argv map[string]interface{}
		token := generateTaskToken()
		switch name {
		case "Agent_Config":
			//If the policy does not exist, use the default policy.
			if hb.Config == nil || len(hb.Config) == 0 {
				hb.Config = defaultConfig
			}

			//Update policy.
			updateConfig(jobParam.ConfigTask, &hb)
			argv = map[string]interface{}{"command": map[string]interface{}{"config": hb.Config}}

			//Write back to db asynchronously.
			task.HBAsyncWrite(&ConnStat{
				AgentInfo: map[string]interface{}{
					"agent_id":           hb.AgentId,
					"config_update_time": time.Now().Unix(),
					"config":             hb.Config,
				},
				PluginsInfo: nil,
			})
		case "Agent_Task":
			item := AgentTaskMsg{
				Name:     jobParam.ConfigTask.Data.Task.Name,
				Data:     jobParam.ConfigTask.Data.Task.Data,
				DataType: jobParam.ConfigTask.Data.Task.DataType,
				Token:    token,
			}
			argv = map[string]interface{}{"command": map[string]interface{}{"task": item}}
		case "Agent_Ctrl":
			argv = map[string]interface{}{"command": map[string]interface{}{"agent_ctrl": jobParam.ConfigTask.Data.AgentCtrl}}
		default:
			ylog.Errorf("agentTaskDistribute", "taskType not support %s", name)
			continue
		}

		//Write the subTask back to db for reconciliation
		subtask := make(map[string]interface{}, 7)
		subtask["task_id"] = jobParam.TaskID
		subtask["agent_id"] = hb.AgentId
		subtask["task_data"] = argv
		subtask["token"] = token
		subtask["status"] = TaskStatusRunning
		subtask["job_id"] = jobParam.JobID
		subtask["update_time"] = time.Now().Unix()
		task.SubTaskUpdateAsyncWrite(subtask)

		port, err := infra.Grds.Get(context.Background(), hb.AgentId).Result()
		if err != nil {
			ylog.Errorf("agentTaskDistribute", "get server addr of %s from redis error %s", hb.AgentId, err.Error())
			port = fmt.Sprintf("%s:%d", hb.SourceIp, hb.SourcePort)
		}
		argv["agent_id"] = hb.AgentId
		innerArgv := map[string]interface{}{"token": token, "argv": argv}
		ja := job.JobArgs{
			Name:    name,
			Host:    port,
			Args:    innerArgv,
			Scheme:  job.ApiMap[name]["scheme"].(string),
			Method:  job.ApiMap[name]["method"].(string),
			Timeout: job.ApiMap[name]["timeout"].(int),
			Path:    job.ApiMap[name]["path"].(string),
		}
		jobs = append(jobs, ja)
	}

	return jobs, nil
}

//
func agentControlDo(args interface{}) (interface{}, error) {
	var (
		r      *grequests.Response
		err    error
		result string
	)
	ja := job.JobArgs{
		Args: make(map[string]interface{}),
	}
	err = json.Unmarshal([]byte(args.(string)), &ja)
	if err != nil {
		ylog.Infof("agentControlDo", "[api_job] do error: %s", err.Error())
		return nil, err
	}

	innerArgv, ok := ja.Args.(map[string]interface{})
	if !ok {
		ylog.Errorf("agentControlDo", "[api_job] AgentJobInnerParam parse error")
		return nil, err
	}

	url := fmt.Sprintf("%s://%s%s", ja.Scheme, ja.Host, ja.Path)
	ylog.Infof("agentControlDo", "[api_jobs] do: %s %s", url, args.(string))

	option := midware.SvrAuthRequestOption()
	option.JSON = innerArgv["argv"]
	option.RequestTimeout = time.Duration(ja.Timeout) * time.Second

	switch ja.Method {
	case job.HttpMethodGet:
		r, err = grequests.Get(url, option)
	case job.HttpMethodPost:
		r, err = grequests.Post(url, option)
	default:
		return nil, errors.New("request method not support")
	}
	if err != nil || r.StatusCode != 200 {
		ylog.Errorf("agentControlDo", "url: %s; args: %s; err: %#v res: %#v", url, args.(string), err, r)
	}

	subTask := make(map[string]interface{}, 4)
	subTask["token"] = innerArgv["token"].(string)
	subTask["task_url"] = url
	subTask["status"] = TaskStatusSuccess
	//http connection error
	if err != nil {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = err.Error()
		task.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	//http error
	if !r.Ok {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("StatusCode is %d", r.StatusCode)
		task.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	svrRsp := &SvrResponse{}
	err = json.Unmarshal(r.Bytes(), svrRsp)
	//repose parse error
	if err != nil {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("%s Unmarshal error %s", r.String(), err.Error())
		task.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	//repose code error
	if svrRsp.Code != 0 {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("svr response error %s", r.String())
		task.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	//success
	subTask["task_resp"] = r.String()
	task.SubTaskUpdateAsyncWrite(subTask)
	return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
}

//Post task:
//	if it is config, modify db at the same time.
//	if it is task, write the task to db(subtask) for reconciliation.
func ControlAgentTask(c *gin.Context) {
	var (
		request AgentTaskControl
		dbTask  AgentConfigTask
		nCount  int
	)

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
			bson.M{"$set": bson.M{"update_time": time.Now().Unix(), "task_status": TaskStatusStopped, "inner_status": TaskStatusStopped}})
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

		//Get the global lock.
		ok, err := infra.DistributedLock(request.TaskID)
		if err != nil {
			common.CreateResponse(c, common.RedisOperateErrorCode, err.Error())
			return
		}
		if !ok {
			common.CreateResponse(c, common.UnknownErrorCode, "Jobs cannot be executed concurrently, please try later")
			return
		}

		//Calculate the count of machines processed by this job
		err = taskCollection.FindOne(context.Background(), bson.M{"task_id": request.TaskID}).Decode(&dbTask)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			infra.DistributedUnLock(request.TaskID)
			return
		}

		if dbTask.InnerStatus == TaskStatusStopped || dbTask.InnerStatus == TaskStatusFinished {
			ylog.Errorf("ControlAgentTask", "%#v", dbTask)
			common.CreateResponse(c, common.UnknownErrorCode, "task is finished/stopped or the todo_list is empty")
			infra.DistributedUnLock(request.TaskID)
			return
		}

		if len(dbTask.ToDoList) == 0 {
			taskCollection.UpdateOne(context.Background(), bson.M{"task_id": dbTask.TaskID}, bson.M{"$set": bson.M{"update_time": dbTask.UpdateTime, "inner_status": TaskStatusFinished}})
			common.CreateResponse(c, common.UnknownErrorCode, "task is finished/stopped or the todo_list is empty")
			infra.DistributedUnLock(request.TaskID)
			return
		}

		if nCount = int(dbTask.IDCount * request.RollingPercent); nCount == 0 {
			nCount = nCount + 1
		}

		if nCount < len(dbTask.ToDoList) {
			dbTask.InnerStatus = TaskStatusRunning
		} else {
			nCount = len(dbTask.ToDoList)
			dbTask.InnerStatus = TaskStatusFinished
		}
		todoList := dbTask.ToDoList[:nCount]
		dbTask.ToDoList = dbTask.ToDoList[nCount:len(dbTask.ToDoList)]
		dbTask.DistributedCount = dbTask.DistributedCount + len(todoList)

		//Create the jod and distribute.
		jID, err := job.NewJob(dbTask.TaskType, request.Concurrence, AgentJobTimeOut, true)
		if err != nil {
			common.CreateResponse(c, common.UnknownErrorCode, err.Error())
			infra.DistributedUnLock(request.TaskID)
			return
		}

		jobParm := AgentJobParam{ConfigTask: &dbTask, TODOList: todoList, TaskID: dbTask.TaskID, JobID: jID}
		//Asynchronous distribution
		go func() {
			job.DistributeJob(jID, dbTask.TaskType, jobParm)
			job.Finish(jID)
			infra.DistributedUnLock(request.TaskID)
		}()

		dbTask.JobList = append(dbTask.JobList, jID)
		dbTask.UpdateTime = time.Now().Unix()
		_, err = taskCollection.UpdateOne(context.Background(), bson.M{"task_id": dbTask.TaskID},
			bson.M{"$set": bson.M{"todo_list": dbTask.ToDoList, "update_time": dbTask.UpdateTime, "task_status": TaskStatusRunning,
				"inner_status": dbTask.InnerStatus, "distributed_count": dbTask.DistributedCount, "job_list": dbTask.JobList}})
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		common.CreateResponse(c, common.SuccessCode, bson.M{"taskID": request.TaskID, "jobID": jID, "id_count": len(todoList)})
	default:
		common.CreateResponse(c, common.ParamInvalidErrorCode, "action only support cancel|run")
	}
}

//不对账
func QuickTaskTask(c *gin.Context) {
	request := &AgentQuickTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("QuickTaskTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	request.Command.Task.Token = ""
	host, err := infra.Grds.Get(c, request.AgentID).Result()
	if err != nil {
		ylog.Errorf("QuickTaskTask", "get server addr of %s from redis error %s", request.AgentID, err.Error())

		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		var heartbeat map[string]interface{}
		err = collection.FindOne(context.Background(), bson.M{"agent_id": request.AgentID}).Decode(&heartbeat)
		if err != nil {
			ylog.Errorf("GetAgentStat Mongodb ", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		tmp, ok := heartbeat["source_ip"]
		if !ok {
			common.CreateResponse(c, common.DBOperateErrorCode, "get Server source_ip Error")
			return
		}
		sip, ok := tmp.(string)
		if !ok {
			common.CreateResponse(c, common.DBOperateErrorCode, "get Server source_ip Error")
			return
		}

		tmp, ok = heartbeat["source_port"]
		if !ok {
			common.CreateResponse(c, common.DBOperateErrorCode, "get Server source_port Error")
			return
		}
		sport := tmp.(int64)
		if !ok {
			common.CreateResponse(c, common.DBOperateErrorCode, "get Server source_port Error")
			return
		}

		host = fmt.Sprintf("%s:%d", sip, sport)
	}

	url := fmt.Sprintf("https://%s/command/", host)
	option := midware.AuthRequestOption()
	option.JSON = request
	option.RequestTimeout = 5 * time.Second
	r, err := grequests.Post(url, option)
	if err != nil {
		ylog.Errorf("QuickTaskTask", "request url %s, data %s,error %s", url, request, err.Error())
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}

	if r.StatusCode != 200 {
		ylog.Errorf("QuickTaskTask", "request url %s, data %s, code %s", url, request, r.StatusCode)
		common.CreateResponse(c, common.UnknownErrorCode, fmt.Sprintf("resp code is %d", r.StatusCode))
		return
	}

	rsp := SvrResponse{}
	err = json.Unmarshal(r.Bytes(), &rsp)
	if err != nil {
		ylog.Errorf("QuickTaskTask", "request url %s, data %s, rsp %d,error %s", url, request, r.String(), err.Error())
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}

	if rsp.Code != 0 {
		common.CreateResponse(c, common.SuccessCode, rsp.Message)
		return
	}

	common.CreateResponse(c, common.SuccessCode, host)
	return
}

func CreateCtrlTask(c *gin.Context) {
	request := &AgentConfigTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	tID, count, err := CreateTask(request, "Agent_Ctrl")
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

func CreateConfTask(c *gin.Context) {
	request := &AgentConfigTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	tID, count, err := CreateTask(request, "Agent_Config")
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

func CreateTaskTask(c *gin.Context) {
	request := &AgentConfigTask{}
	err := c.BindJSON(request)
	if err != nil {
		ylog.Errorf("CreateAgentTask", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	tID, count, err := CreateTask(request, "Agent_Task")
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

	task := &AgentConfigTask{
		Tag:    request.Tag,
		IDList: request.IDList,
		Data: ConfigRequest{
			AgentCtrl: 0,
			Config:    make([]AgentConfigMsg, len(request.Data)),
		},
	}
	for k, v := range request.Data {
		task.Data.Config[k] = AgentConfigMsg{
			Name: v,
		}
	}

	tID, count, err := CreateTask(task, "Agent_Config")
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"task_id": tID, "count": count})
}

func CreateTask(request *AgentConfigTask, tType string) (string, float64, error) {
	if request.IDList == nil {
		request.IDList = []string{}
	}
	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)

	var filter bson.M
	if request.Filter == nil {
		filter = bson.M{"$or": []bson.M{{"tags": request.Tag}, {"agent_id": bson.M{"$in": request.IDList}}}}
	} else {
		filter = bson.M{"$or": []bson.M{{"tags": request.Tag}, {"agent_id": bson.M{"$in": request.IDList}}, request.Filter.Transform()}}
	}

	cursor, err := agentCollection.Find(context.Background(), filter)
	if err != nil {
		ylog.Errorf("createTask", err.Error())
		return "", 0, err
	}
	defer cursor.Close(context.Background())
	todoList := make([]string, 0, 1024)
	agentIDMap := make(map[string]bool, 2000)
	taskID := fmt.Sprintf(`%d%s`, time.Now().UnixNano(), infra.RandStringBytes(6))
	for cursor.Next(context.Background()) {
		var hb AgentHBInfo
		err := cursor.Decode(&hb)
		if err != nil {
			ylog.Errorf("createTask", err.Error())
			continue
		}

		//数据同时更新和查询，会导致返回重复数据，确保不重复
		if _, ok := agentIDMap[hb.AgentId]; ok {
			continue
		} else {
			agentIDMap[hb.AgentId] = true
		}

		ylog.Debugf("createTask", "heartbeat: %#v", hb)
		todoList = append(todoList, hb.AgentId)

		//Write the subTask back to db for reconciliation
		tmp := &AgentSubTask{
			TaskType:   tType,
			AgentID:    hb.AgentId,
			TaskID:     taskID,
			TaskUrl:    "",
			Status:     TaskStatusCreated,
			UpdateTime: time.Now().Unix(),
			TaskResult: "",
		}
		//TODO 这里为了性能做了异步处理，可能会有隐患
		task.SubTaskAsyncWrite(tmp)
	}

	//将此次任务记录写回db
	request.InnerStatus = TaskStatusCreated
	request.TaskStatus = TaskStatusCreated
	request.ToDoList = todoList
	request.TaskType = tType
	request.JobList = []string{}
	request.CreateTime = time.Now().Unix()
	request.UpdateTime = time.Now().Unix()
	request.IDCount = float64(len(todoList))
	request.TaskID = taskID
	request.DistributedCount = 0

	taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	taskCollection.InsertOne(context.Background(), request)
	return request.TaskID, request.IDCount, nil
}

func generateTaskToken() string {
	guid := xid.New()
	return guid.String()
}

func updateConfig(dbTask *AgentConfigTask, hb *AgentHBInfo) {
	for k, v := range dbTask.Data.Config {
		hit := false
		for k1, v1 := range hb.Config {
			if v1.Name == v.Name {
				hit = true
				//delete
				if len(dbTask.Data.Config[k].DownloadURL) == 0 && dbTask.Data.Config[k].Version == "" &&
					dbTask.Data.Config[k].SHA256 == "" && dbTask.Data.Config[k].Detail == "" {
					hb.Config = append(hb.Config[:k1], hb.Config[k1+1:]...)
					break
				}

				//update
				if v.DownloadURL != nil && len(v.DownloadURL) != 0 {
					hb.Config[k1].DownloadURL = dbTask.Data.Config[k].DownloadURL
				}
				if v.Version != "" {
					hb.Config[k1].Version = dbTask.Data.Config[k].Version
				}
				if v.SHA256 != "" {
					hb.Config[k1].SHA256 = dbTask.Data.Config[k].SHA256
				}
				if v.Detail != "" {
					hb.Config[k1].Detail = dbTask.Data.Config[k].Detail
				}
				if v.Type != "" {
					hb.Config[k1].Type = dbTask.Data.Config[k].Type
				}
				break
			}
		}

		//new config item
		if !hit {
			//all is empty
			if len(dbTask.Data.Config[k].DownloadURL) == 0 && dbTask.Data.Config[k].Version == "" &&
				dbTask.Data.Config[k].SHA256 == "" && dbTask.Data.Config[k].Detail == "" {
				continue
			}
			hb.Config = append(hb.Config, dbTask.Data.Config[k])
		}
	}
}

//GetTaskByID return task task_id.
func GetTaskByID(c *gin.Context) {
	var task AgentConfigTaskAll
	taskID := c.Param("id")
	collTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	err := collTask.FindOne(context.Background(), bson.M{"task_id": taskID}).Decode(&task)
	if err != nil && err != mongo.ErrNoDocuments {
		ylog.Errorf("GetTaskByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	err = ComputeSubTaskStat(&task)
	if err != nil {
		ylog.Errorf("GetTaskByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, nil)
		return
	}

	task.ToDoList = []string{}
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
			var task AgentConfigTaskAll
			err := cursor.Decode(&task)
			if err != nil {
				ylog.Errorf("GetTaskByFilter", err.Error())
				return nil, err
			}

			err = ComputeSubTaskStat(&task)
			if err != nil {
				ylog.Errorf("GetTaskByFilter", err.Error())
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

//TODO 待优化性能
func ComputeSubTaskStat(task *AgentConfigTaskAll) error {
	var res = make([]SubTaskCount, 3)
	collSubTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"task_id", task.TaskID}}}},
		{{"$group", bson.D{{"_id", "$status"}, {"count", bson.D{{"$sum", 1}}}}}},
	}
	opts := options.Aggregate().SetMaxTime(15 * time.Second)
	cursor, err := collSubTask.Aggregate(context.TODO(), pipeline, opts)
	if err != nil {
		return err
	}

	err = cursor.All(context.Background(), &res)
	if err != nil {
		return err
	}

	task.SubTaskCreated = 0
	task.SubTaskSucceed = 0
	task.SubTaskFailed = 0
	task.SubTaskRunning = 0
	for _, v := range res {
		if v.ID == TaskStatusCreated {
			task.SubTaskCreated = v.Count
		} else if v.ID == TaskStatusSuccess {
			task.SubTaskSucceed = v.Count
		} else if v.ID == TaskStatusFail {
			task.SubTaskFailed = v.Count
		} else if v.ID == TaskStatusRunning {
			task.SubTaskRunning = v.Count
		}
	}

	//未取消+未处于新建状态+没有正在运行的子任务
	if task.InnerStatus != TaskStatusStopped && task.DistributedCount != 0 && task.SubTaskRunning == 0 && (task.DistributedCount == (task.SubTaskSucceed + task.SubTaskFailed)) {
		task.TaskStatus = TaskStatusFinished
	}

	//write back db
	collTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	_, err = collTask.UpdateOne(context.Background(), bson.M{"task_id": task.TaskID}, bson.M{"$set": bson.M{"sub_task_created": task.SubTaskCreated,
		"sub_task_failed": task.SubTaskFailed, "sub_task_succeed": task.SubTaskSucceed, "sub_task_running": task.SubTaskRunning, "task_status": task.TaskStatus}})
	if err != nil {
		ylog.Errorf("GetTaskByID", err.Error())
	}

	return nil
}

//GetTaskByID return agent config by agent_id.
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

// 按照机器数量控制任务
func ControlAgentTaskByNum(c *gin.Context) {

	type AgentTaskControl struct {
		TaskID      string `json:"task_id" binding:"required" bson:"task_id"`
		Action      string `json:"action" binding:"required" bson:"action"`
		RunNumber   int    `json:"run_number" binding:"required" bson:"run_number"`
		Concurrence int    `json:"concurrence" binding:"required" bson:"concurrence"`
	}
	var (
		request AgentTaskControl
		dbTask  AgentConfigTask
		nCount  int
	)

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
			bson.M{"$set": bson.M{"update_time": time.Now().Unix(), "task_status": TaskStatusStopped, "inner_status": TaskStatusStopped}})
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

		//Get the global lock.
		ok, err := infra.DistributedLock(request.TaskID)
		if err != nil {
			common.CreateResponse(c, common.RedisOperateErrorCode, err.Error())
			return
		}
		if !ok {
			common.CreateResponse(c, common.UnknownErrorCode, "Jobs cannot be executed concurrently, please try later")
			return
		}

		//Calculate the count of machines processed by this job
		err = taskCollection.FindOne(context.Background(), bson.M{"task_id": request.TaskID}).Decode(&dbTask)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			infra.DistributedUnLock(request.TaskID)
			return
		}

		if dbTask.InnerStatus == TaskStatusStopped || dbTask.InnerStatus == TaskStatusFinished {
			common.CreateResponse(c, common.UnknownErrorCode, "task is finished/stopped or the todo_list is empty")
			infra.DistributedUnLock(request.TaskID)
			return
		}

		if len(dbTask.ToDoList) == 0 {
			taskCollection.UpdateOne(context.Background(), bson.M{"task_id": dbTask.TaskID}, bson.M{"$set": bson.M{"update_time": dbTask.UpdateTime, "inner_status": TaskStatusFinished}})
			common.CreateResponse(c, common.UnknownErrorCode, "task is finished/stopped or the todo_list is empty")
			infra.DistributedUnLock(request.TaskID)
			return
		}

		nCount = request.RunNumber

		if nCount < len(dbTask.ToDoList) {
			dbTask.TaskStatus = TaskStatusRunning
		} else {
			nCount = len(dbTask.ToDoList)
			dbTask.TaskStatus = TaskStatusFinished
		}
		todoList := dbTask.ToDoList[:nCount]
		dbTask.ToDoList = dbTask.ToDoList[nCount:len(dbTask.ToDoList)]
		dbTask.DistributedCount = dbTask.DistributedCount + len(todoList)

		//Create the jod and distribute.
		jID, err := job.NewJob(dbTask.TaskType, request.Concurrence, AgentJobTimeOut, true)
		if err != nil {
			common.CreateResponse(c, common.UnknownErrorCode, err.Error())
			infra.DistributedUnLock(request.TaskID)
			return
		}
		jobParm := AgentJobParam{ConfigTask: &dbTask, TODOList: todoList, TaskID: dbTask.TaskID, JobID: jID}
		//异步分发
		go func() {
			job.DistributeJob(jID, dbTask.TaskType, jobParm)
			job.Finish(jID)

			//释放锁
			infra.DistributedUnLock(request.TaskID)
		}()

		dbTask.JobList = append(dbTask.JobList, jID)
		dbTask.UpdateTime = time.Now().Unix()
		_, err = taskCollection.UpdateOne(context.Background(), bson.M{"task_id": dbTask.TaskID},
			bson.M{"$set": bson.M{"todo_list": dbTask.ToDoList, "update_time": dbTask.UpdateTime, "task_status": TaskStatusRunning,
				"inner_status": dbTask.InnerStatus, "distributed_count": dbTask.DistributedCount, "job_list": dbTask.JobList}})
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, bson.M{"taskID": request.TaskID, "jobID": jID, "id_count": len(todoList), "error": err.Error()})
			return
		}

		common.CreateResponse(c, common.SuccessCode, bson.M{"taskID": request.TaskID, "jobID": jID, "id_count": len(todoList)})
	default:
		common.CreateResponse(c, common.ParamInvalidErrorCode, "action only support cancel|run")
	}
}
