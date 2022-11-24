package v6

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/alarm"
	"github.com/bytedance/Elkeid/server/manager/internal/alarm_whitelist"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"github.com/bytedance/Elkeid/server/manager/internal/virus_detection"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"

	"github.com/gin-gonic/gin"
)

// ********************************* struct *********************************
type VirusScanAlarmListItem struct {
	AlarmId   string        `json:"alarm_id"`
	AgentId   string        `json:"agent_id"`
	Status    int           `json:"status"`
	Type      string        `json:"type"`
	Name      string        `json:"name"`
	Level     string        `json:"level"`
	HostName  string        `json:"alarm_hostname"`
	AlarmTime int64         `json:"alarm_time"`
	Host      AlarmHostInfo `json:"host"`
	FilePath  string        `json:"file_path"`
	FileHash  string        `json:"file_hash"`
	ErrReason string        `json:"error_reason,omitempty"`
}

type VirusScanTaskListFilter struct {
	TaskName   string   `json:"task_name,omitempty" bson:"task_name,omitempty"`
	TaskStatus []string `json:"task_status,omitempty" bson:"task_status,omitempty"`
	Action     []string `json:"action,omitempty" bson:"action,omitempty"`
	TaskUser   string   `json:"task_user,omitempty" bson:"task_user,omitempty"`
	FilePath   string   `json:"file_path,omitempty" bson:"file_path,omitempty"`
}

type VirusScanTaskListRequest struct {
	VirusScanTaskListFilter `json:",inline" bson:",inline"`
}

type VirusScanTaskOptRequest struct {
	TaskId string `json:"task_id" bson:"exe"`
	Opt    string `json:"opt" bson:"opt"`
}

type VirusScanTaskHostListRequest struct {
	TaskId   string `json:"task_id" bson:"task_id"`
	HostName string `json:"hostname,omitempty" bson:"hostname,omitempty"`
	IP       string `json:"ip,omitempty" bson:"ip,omitempty"`
}

type VirusAlarmListRequest struct {
	AlarmListRequest `json:",inline"`
	TaskId           *string `json:"task_id,omitempty"`
}

type VirusTaskDetail struct {
	TaskDetail `json:",inline" bson:",inline"`
	FilePath   string `json:"file_path" bson:"file_path"`
}

type VirusSubTaskInfo struct {
	TaskId  string `json:"task_id" bson:"task_id"`
	AgentId string `json:"agent_id" bson:"agent_id"`
	Token   string `json:"token" bson:"token"`
}

type VirusSubTaskListRequest struct {
	TaskId   string   `json:"task_id" bson:"task_id"`
	Status   []string `json:"status,omitempty" bson:"status,omitempty"`
	Hostname string   `json:"hostname,omitempty" bson:"hostname,omitempty"`
}

type VirusSubTaskListItem struct {
	TaskId     string `json:"task_id" bson:"task_id"`
	AgentId    string `json:"agent_id" bson:"agent_id"`
	Status     string `json:"status" bson:"status"`
	Hostname   string `json:"hostname" bson:"hostname"`
	UpdateTime int64  `json:"update_time" bson:"update_time"`
	FailReason string `json:"fail_reason,omitempty" bson:"fail_reason,omitempty"`
}

type VirusSubTaskResult struct {
	Msg string `json:"msg,omitempty" bson:"msg,omitempty"`
}

type VirusSubTaskDetail struct {
	TaskId     string `json:"task_id" bson:"task_id"`
	AgentId    string `json:"agent_id" bson:"agent_id"`
	Status     string `json:"status" bson:"status"`
	Hostname   string `json:"hostname" bson:"hostname"`
	UpdateTime int64  `json:"update_time" bson:"update_time"`
}

type VirusSubTaskDetailWithResult struct {
	TaskId     string             `json:"task_id" bson:"task_id"`
	AgentId    string             `json:"agent_id" bson:"agent_id"`
	Status     string             `json:"status" bson:"status"`
	Hostname   string             `json:"hostname" bson:"hostname"`
	UpdateTime int64              `json:"update_time" bson:"update_time"`
	TaskResult VirusSubTaskResult `json:"task_result" bson:"task_result"`
}

type VirusSubTaskName struct {
	AgentId  string `bson:"agent_id"`
	Hostname string `bson:"hostname"`
}

type VirusSubTaskAndAgentJoinResult struct {
	VirusSubTaskDetail `json:",inline" bson:",inline"`
	InventoryDocs      []VirusSubTaskName `json:"inventory_docs" bson:"inventory_docs"`
}

type VirusSubTaskWithResultAndAgentJoin struct {
	VirusSubTaskDetailWithResult `json:",inline" bson:",inline"`
	InventoryDocs                []VirusSubTaskName `json:"inventory_docs" bson:"inventory_docs"`
}

type VirusTaskRunConfig struct {
	FilePath string `json:"file_path,omitempty" bson:"file_path,omitempty"`
	CpuIdle  string `json:"cpu_idle,omitempty" bson:"cpu_idle,omitempty"`
	Timeout  string `json:"timeout,omitempty" bson:"timeout,omitempty"`
}

type VirusTaskRunningInfo struct {
	Tag              string             `json:"tag" bson:"tag"`
	IDList           []string           `json:"id_list" bson:"id_list"`
	TaskName         string             `json:"task_name" bson:"task_name"`
	TaskID           string             `json:"task_id" bson:"task_id"`
	TaskType         string             `json:"task_type" bson:"task_type"`
	TaskStatus       string             `json:"task_status" bson:"task_status"` //记录任务状态
	IDCount          float64            `json:"id_count" bson:"id_count"`
	DistributedCount int                `json:"distributed_count" bson:"distributed_count"` //下发总数，可能未执行完成
	Action           string             `json:"action" bson:"action"`
	TaskUser         string             `json:"task_user" bson:"task_user"`
	SubTaskCreated   int                `json:"sub_task_created" bson:"sub_task_created"`
	SubTaskRunning   int                `json:"sub_task_running" bson:"sub_task_running"`
	SubTaskFailed    int                `json:"sub_task_failed" bson:"sub_task_failed"`
	SubTaskSucceed   int                `json:"sub_task_succeed" bson:"sub_task_succeed"`
	CreateTime       int64              `json:"create_time" bson:"create_time"`
	UpdateTime       int64              `json:"update_time" bson:"update_time"`
	Config           VirusTaskRunConfig `json:"config" bson:"config"`
}

type VirusHostInfo struct {
	HostName    string   `json:"hostname"`
	InnerIpList []string `json:"inner_ip_list"`
	OuterIpList []string `json:"outer_ip_list"`
	AgentId     string   `json:"agent_id"`
}

// ********************************* Summary *********************************
func GetAlarmSummaryInfoForVirus(c *gin.Context) {
	GetAlarmSummaryInfo(c, alarm.AlarmTypeVirus)
}

// ********************************* Alarm stat *********************************
func GetAlarmStatForVirus(c *gin.Context) {
	GetAlarmStat(c, alarm.AlarmTypeVirus)
}

// ********************************* update alarm status *********************************
func UpdateAlarmStatusManyForVirus(c *gin.Context) {
	UpdateAlarmStatusMany(c, alarm.AlarmTypeVirus)
}

// ********************************* alarm export *********************************
func ExportAlarmListDataForVirus(c *gin.Context) {

	exportFileName := "Exported-VirusAlarm"

	var exportHeaders = common.MongoDBDefs{
		{Key: "rule_name", Header: "rule_name"},
		{Key: "alert_type_us", Header: "type"},
		{Key: "harm_level", Header: "level"},
		{Key: "__alarm_status", Header: "status"},
		{Key: "hostname", Header: "hostname"},
		{Key: "static_file", Header: "file_name"},
		{Key: "md5_hash", Header: "file_hash"},
		{Key: "__insert_time", Header: "alarm_time"},
	}

	ExportAlarmListData(c, alarm.AlarmTypeVirus, exportHeaders, exportFileName)
}

// ********************************* alarm list *********************************
func GetAlarmListForVirus(c *gin.Context) {
	GetAlarmList(c, alarm.AlarmTypeVirus)
}

// ********************************* filter by white *********************************
func GetAlarmFilterByWhiteForVirus(c *gin.Context) {
	GetAlarmFilterByWhite(c, alarm.AlarmTypeVirus)
}

// ********************************* whitelist *********************************
func GetWhiteListWithCombineForVirus(c *gin.Context) {
	GetWhiteListWithCombine(c, alarm_whitelist.WhitelistTypeVirus)
}

func MultiAddWhiteListWithCombineForVirus(c *gin.Context) {
	WhiteListAddMultiWithCombine(c, alarm_whitelist.WhitelistTypeVirus)
}

func MultiDelWhiteListForVirus(c *gin.Context) {
	WhiteListDelMulti(c, alarm_whitelist.WhitelistTypeVirus)
}

// ********************************* task opt *********************************

func RunTaskProcess(task_id string) {
	// wait 5s to run
	time.Sleep(5 * time.Second)
	_, _, err := atask.RunTask(task_id, 100, 0, 5)
	if err != nil {
		ylog.Errorf("run virus scan task error", "task_id %s error %s", task_id, err.Error())
		return
	}

	ylog.Infof("run virus scan task success", "task_id %s", task_id)
}

// ********************************* scan task *********************************
func CreatFileScanTaskForVirus(c *gin.Context) {
	var rsp CreateTaskResponse
	// 生成任务信息
	createTask := &CreateFileScanTaskRequest{}
	err := c.BindJSON(createTask)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	operateUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}

	// 补全任务信息
	virusScanTask := &atask.AgentTask{}
	virusScanTaskData := AgentTaskMsg{
		Name: "scanner",
	}
	taskDataContent := virus_detection.VirusScanTaskDataContent{}
	switch createTask.Action {
	case virus_detection.VirusScanTaskTypeQuick:
		virusScanTaskData.DataType = virus_detection.VirusScanDataTypeQuick
		taskDataContent.Mode = "quick"
		taskDataContent.CpuIdle = createTask.CpuIdle
		taskDataContent.Timeout = createTask.Timeout
	case virus_detection.VirusScanTaskTypeFull:
		virusScanTaskData.DataType = virus_detection.VirusScanDataTypeFull
		taskDataContent.Mode = "full"
		taskDataContent.CpuIdle = createTask.CpuIdle
		taskDataContent.Timeout = createTask.Timeout
	case virus_detection.VirusScanTaskTypeFile:
		if createTask.FilePath == "" {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "empty file path")
			return
		}
		virusScanTaskData.DataType = virus_detection.VirusScanDataTypeFile
		taskDataContent.Exe = createTask.FilePath
	default:
		common.CreateResponse(c, common.ParamInvalidErrorCode, "unknown action")
		return
	}

	taskDataContentStr, _ := json.Marshal(&taskDataContent)
	virusScanTaskData.Data = string(taskDataContentStr)
	virusScanTask.Data.Task = virusScanTaskData
	virusScanTask.Action = createTask.Action
	virusScanTask.TaskName = createTask.TaskName
	// 生成任务下发主机列表
	if len(createTask.IdList) != 0 {
		virusScanTask.IDList = createTask.IdList
	} else {
		filter := createTask.GenerateFilter()
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
			virusScanTask.IDList = append(virusScanTask.IDList, idStruct.AgentId)
		}
	}

	// 记录操作用户
	virusScanTask.TaskUser = operateUser.(string)

	// 下发任务
	tID, count, err := atask.CreateTaskTask(virusScanTask)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	rsp.TaskId = tID
	rsp.TaskCount = int(count)

	go RunTaskProcess(tID)

	common.CreateResponse(c, common.SuccessCode, rsp)
}

func GetTaskListForVirus(c *gin.Context) {

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
	var taskRequest VirusScanTaskListRequest
	err = c.BindJSON(&taskRequest)
	if err != nil {
		ylog.Errorf("GetTaskListForVirus", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}
	ylog.Infof("func GetTaskListForVirus request", "%+v", taskRequest)
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
		searchFilter["action"] = common.MongoInside{Inside: virus_detection.VirusTaskActionList}
	}
	if taskRequest.TaskUser != "" {
		searchFilter["task_user"] = common.MongoRegex{Regex: taskRequest.TaskUser}
	}
	if taskRequest.FilePath != "" {
		searchFilter["data.task.data"] = common.MongoRegex{Regex: taskRequest.FilePath}
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	pageSearch := common.PageSearch{
		Page:     pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   searchFilter,
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}
	ylog.Debugf("func GetTaskListForVirus filter", "%+v", searchFilter)
	// mongo查询并迭代处理
	var dataResponse []VirusTaskDetail
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			// 更新子任务状态
			var task atask.AgentTask
			err := cursor.Decode(&task)
			if err != nil {
				ylog.Errorf("func getTaskListForVirus db decode error", err.Error())
				return err
			}

			var scanFilePath = ""
			// check task type
			if task.Data.Task.DataType == virus_detection.VirusScanDataTypeFile {
				// get path
				tmpData := make(map[string]interface{}, 0)
				err = json.Unmarshal([]byte(task.Data.Task.Data), &tmpData)
				if err != nil {
					ylog.Errorf("func getTaskListForVirus task data decode error", err.Error())
					return err
				}

				_, pOk := tmpData["exe"]
				if pOk {
					tmpPath, sOk := tmpData["exe"].(string)
					if sOk {
						scanFilePath = tmpPath
					}
				}
			}

			var taskInfo VirusTaskDetail
			taskInfo.TaskId = task.TaskID
			taskInfo.Action = task.Action
			taskInfo.TaskUser = task.TaskUser
			taskInfo.Tag = task.Tag
			taskInfo.TaskStatus = task.TaskStatus
			taskInfo.TaskName = task.TaskName
			taskInfo.IdCount = int(task.IDCount)
			taskInfo.SubTaskCreated = task.SubTaskCreated
			taskInfo.SubTaskFailed = task.SubTaskFailed
			taskInfo.SubTaskSucceed = task.SubTaskSucceed
			taskInfo.UpdateTime = task.UpdateTime
			taskInfo.CreateTime = task.CreateTime
			taskInfo.FilePath = scanFilePath

			// append out
			dataResponse = append(dataResponse, taskInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetTaskListForVirus", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

func GetTaskHostListForVirus(c *gin.Context) {
	listReq := &VirusScanTaskHostListRequest{}
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = c.BindJSON(listReq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	queryTaskJs := bson.M{"task_id": bson.M{"$eq": listReq.TaskId}}
	taskData := &atask.AgentTask{}
	taskCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	err = taskCol.FindOne(c, queryTaskJs).Decode(taskData)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// query agent info from agent_heartbeat
	queryHostJs := bson.M{"agent_id": bson.M{"$in": taskData.IDList}}
	if listReq.HostName != "" {
		queryHostJs["hostname"] = bson.M{"$regex": listReq.HostName}
	}
	if listReq.IP != "" {
		queryHostJs["$or"] = bson.M{
			"intranet_ipv4": bson.M{"$regex": listReq.IP},
			"intranet_ipv6": bson.M{"$regex": listReq.IP},
			"extranet_ipv4": bson.M{"$regex": listReq.IP},
			"extranet_ipv6": bson.M{"$regex": listReq.IP},
		}
	}
	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	pageSearch := common.PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   queryHostJs,
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default sort value
		pageSearch.Sorter = bson.M{"_id": -1}
	}
	ylog.Infof("getTaskHostListForVirus", "%v", taskData.IDList)
	var hostList = make([]VirusHostInfo, 0, 100)
	pageResponse, err := common.DBSearchPaginate(
		hbCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var rawHostInfo asset_center.AgentBasicInfo
			err = cursor.Decode(&rawHostInfo)
			if err != nil {
				ylog.Errorf("GetAlarmListForVirus error", err.Error())
				return err
			}
			ylog.Infof("getTaskHostListForVirus", "%s", rawHostInfo.AgentID)
			oneHost := VirusHostInfo{
				HostName:    rawHostInfo.Hostname,
				AgentId:     rawHostInfo.AgentID,
				InnerIpList: make([]string, 0, 10),
				OuterIpList: make([]string, 0, 10),
			}

			if len(rawHostInfo.IntranetIPv4) > 0 {
				oneHost.InnerIpList = append(oneHost.InnerIpList, rawHostInfo.IntranetIPv4...)
			}

			if len(rawHostInfo.IntranetIPv6) > 0 {
				oneHost.InnerIpList = append(oneHost.InnerIpList, rawHostInfo.IntranetIPv6...)
			}

			if len(rawHostInfo.ExtranetIPv4) > 0 {
				oneHost.OuterIpList = append(oneHost.OuterIpList, rawHostInfo.ExtranetIPv4...)
			}

			if len(rawHostInfo.ExtranetIPv6) > 0 {
				oneHost.OuterIpList = append(oneHost.OuterIpList, rawHostInfo.ExtranetIPv6...)
			}

			hostList = append(hostList, oneHost)
			return nil
		},
	)

	CreatePageResponse(c, common.SuccessCode, hostList, *pageResponse)
}

func GetTaskStatisticsForVirus(c *gin.Context) {
	var rsp virus_detection.VirusScanTaskStatistics

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VirusDetectionTaskStatCollectionV1)
	err := collection.FindOne(c, bson.M{}).Decode(&rsp)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, rsp)
}

func TransVirusTaskStatusToWebTaskStatus(status string) string {
	var retStatus = ""

	switch status {
	case atask.TaskStatusSuccess, atask.TaskStatusRunning:
		retStatus = atask.TaskStatusRunning
	case atask.TaskStatusFail, atask.TaskStatusResultFail:
		retStatus = atask.TaskStatusFail
	case atask.TaskStatusResultSuccess:
		retStatus = atask.TaskStatusSuccess
	default:
		retStatus = status
	}

	return retStatus
}

func GetSubTaskListForVirus(c *gin.Context) {
	// 绑定分页数据
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetSubTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定任务筛选数据
	var subTaskRequest VirusSubTaskListRequest
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

	var dataResponse []VirusSubTaskListItem
	pageResponse, err := common.DBAggregatePaginate(
		collection,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			v := VirusSubTaskAndAgentJoinResult{}
			dErr := cursor.Decode(&v)
			if dErr != nil {
				ylog.Errorf("deco VirusSubTaskAndAgentJoinResult error", dErr.Error())
				return nil
			}
			var subTaskInfo VirusSubTaskListItem
			taskStatus := TransVirusTaskStatusToWebTaskStatus(v.Status)
			subTaskInfo.TaskId = v.TaskId
			subTaskInfo.AgentId = v.AgentId
			subTaskInfo.Status = taskStatus
			subTaskInfo.UpdateTime = v.UpdateTime
			if len(v.InventoryDocs) > 0 {
				agentInfo := v.InventoryDocs[0]
				subTaskInfo.Hostname = agentInfo.Hostname
			}

			subTaskInfo.FailReason = ""
			if taskStatus == "failed" {
				r := VirusSubTaskWithResultAndAgentJoin{}
				dErr = cursor.Decode(&r)
				if dErr != nil {
					ylog.Errorf("deco VirusSubTaskWithResultAndAgentJoin error", dErr.Error())
				} else {
					subTaskInfo.FailReason = r.TaskResult.Msg
				}
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

func GetVirusTaskByID(c *gin.Context) {
	var task atask.AgentTask
	taskID := c.Param("id")
	collTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	err := collTask.FindOne(context.Background(), bson.M{"task_id": taskID}).Decode(&task)
	if err != nil && err != mongo.ErrNoDocuments {
		ylog.Errorf("query db for GetTaskByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	var scanFilePath = ""
	var scanCpuIdle = ""
	var scanTimeout = ""

	tmpData := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(task.Data.Task.Data), &tmpData)
	if err != nil {
		ylog.Errorf("decode data for GetTaskByID", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// decode the data
	if task.Data.Task.DataType == virus_detection.VirusScanDataTypeFile {
		// decode file path
		tmpPath, dOk := tmpData["exe"]
		if dOk {
			tmpPathStr, tOk := tmpPath.(string)
			if tOk {
				scanFilePath = tmpPathStr
			}
		}
	}

	if task.Data.Task.DataType == virus_detection.VirusScanDataTypeQuick {
		// decode cpu and timeout
		tmpCpu, cOk := tmpData["cpu_idle"]
		if cOk {
			tmpCpuStr, tOk := tmpCpu.(string)
			if tOk {
				scanCpuIdle = tmpCpuStr
			}
		}
		tmpTimeout, tOk := tmpData["timeout"]
		if tOk {
			tmpTimeoutStr, tOk := tmpTimeout.(string)
			if tOk {
				scanTimeout = tmpTimeoutStr
			}
		}
	}

	var taskRunInfo = VirusTaskRunningInfo{
		IDList:           task.IDList,
		TaskName:         task.TaskName,
		TaskID:           task.TaskID,
		TaskType:         task.TaskType,
		TaskStatus:       task.TaskStatus,
		IDCount:          task.IDCount,
		DistributedCount: task.DistributedCount,
		Action:           task.Action,
		TaskUser:         task.TaskUser,
		SubTaskCreated:   task.SubTaskCreated,
		SubTaskRunning:   task.SubTaskRunning,
		SubTaskFailed:    task.SubTaskFailed,
		SubTaskSucceed:   task.SubTaskSucceed,
		CreateTime:       task.CreateTime,
		UpdateTime:       task.UpdateTime,
		Config: VirusTaskRunConfig{
			FilePath: scanFilePath,
			CpuIdle:  scanCpuIdle,
			Timeout:  scanTimeout,
		},
	}

	task.ToDoList = []string{}
	common.CreateResponse(c, common.SuccessCode, taskRunInfo)
}

func WhiteListUpdateOneForVirus(c *gin.Context) {
	WhiteListUpdateOne(c, alarm_whitelist.WhitelistTypeVirus)
}
