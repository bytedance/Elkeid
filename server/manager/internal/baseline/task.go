package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// 基线任务下发
type taskResp struct {
	ID   string `json:"id"`
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// 心跳
type HB struct {
	AgentId string                   `json:"agent_id" bson:"agent_id"`
	Plugin  []map[string]interface{} `json:"plugins" bson:"plugins"`
}

// 判断插件是否在线
func isPluginOnline(pluginName string, list []map[string]interface{}) bool {
	for _, v := range list {
		if name, ok := v["name"].(string); ok && name == pluginName {
			return true
		}
	}
	return false
}

// 下发基线任务
func SendBaselineTask(agentIdList []string, user string, taskMsg def.AgentTaskMsg) (taskResList []taskResp, err error) {
	c := context.Background()
	runList := make([]string, 0, len(agentIdList))
	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	searchFilter := bson.M{}
	searchFilter["last_heartbeat_time"] = bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}
	if len(agentIdList) != 0 {
		searchFilter["agent_id"] = bson.M{"$in": agentIdList}
	} else {
		return
	}
	findOpt := options.FindOptions{}
	findOpt.Projection = bson.M{"agent_id": 1, "plugins": 1}
	cursor, err := hbCol.Find(c, searchFilter, &findOpt)
	for cursor.Next(context.Background()) {
		var hb HB
		err := cursor.Decode(&hb)
		if err != nil {
			continue
		}
		taskRes := taskResp{
			ID:   hb.AgentId,
			Code: 0,
			Msg:  "",
		}

		// 判断基线插件是否存在
		if !isPluginOnline(taskMsg.Name, hb.Plugin) {
			taskRes.Code = -1
			taskRes.Msg = fmt.Sprintf("The dependent plugin %s is not online.", taskMsg.Name)
		}
		taskResList = append(taskResList, taskRes)
		runList = append(runList, hb.AgentId)
	}

	// 下发任务
	if len(runList) == 0 {
		return
	}
	taskParam := atask.AgentTask{
		IDList:   runList,
		TaskName: taskMsg.Name,
		TaskUser: user,
		Data: def.ConfigRequest{
			Task: taskMsg,
		},
	}

	_, _, err = atask.CreateTaskAndRun(&taskParam, atask.TypeAgentTask, 5)
	if err != nil {
		ylog.Errorf("SendBaselineTask", err.Error())
		return
	}
	time.Sleep(5 * time.Second)

	return
}

// 开始基线检查
type CheckRequest struct {
	GroupId    int      `json:"group_id"`
	BaselineId int      `json:"baseline_id"`
	HostList   []string `json:"host_list"`
	CheckList  []int    `json:"check_list"`
	User       string   `json:"user"`
}

func StartCheck(checkRequest CheckRequest) (err error) {
	c := context.Background()
	startTime := time.Now().UnixNano()
	type AgentStruct struct {
		AgentId string `json:"agent_id" bson:"agent_id"`
	}

	// 初始化一个弱口令的agentBaseline 数据
	weakPassAgentBaseline := AgentBaselineInfo{
		BaselineId:      WeakPassBaseline,
		CheckId:         1,
		BaselineVersion: "1.0",
		CheckLevel:      BaselineCheckHigh,
		Type:            "WeakPassword",
		CheckName:       "System login weak password detection",
		Description:     "Check if the system login is a weak password.",
		Solution:        "Change the password used for system login, it is recommended to use uppercase and lowercase + special character passwords.",
		TypeCn:          "弱口令",
		CheckNameCn:     "系统登录弱口令检测",
		DescriptionCn:   "检查系统登录是否为弱口令。",
		SolutionCn:      "更改系统登录所使用的的口令，建议使用大小写+特殊字符的密码",
		CreateTime:      0,
		UpdateTime:      time.Now().Unix(),
		Status:          "passed",
	}

	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	baselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
	checkInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineCheckInfoColl)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)

	// 获取待检查基线列表
	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	baselineIdList := make([]int, 0)
	if checkRequest.BaselineId != 0 {
		baselineIdList = append(baselineIdList, checkRequest.BaselineId)
	} else if checkRequest.GroupId != 0 {
		var groupInfo GroupInfo
		err := groupCol.FindOne(c, bson.M{"group_id": checkRequest.GroupId}).Decode(&groupInfo)
		if err != nil {
			ylog.Infof("Find error", err.Error())
		}
		for _, baselineInfo := range groupInfo.BaselineList {
			baselineIdList = append(baselineIdList, baselineInfo.BaselineId)
		}
	} else {
		return
	}

	// 依次下发基线任务
	taskStatusWrite := make([]mongo.WriteModel, 0, len(checkRequest.HostList)*len(baselineIdList))
	checkTaskWrite := make([]mongo.WriteModel, 0, len(checkRequest.HostList)*len(baselineIdList)*20)

	baselineCheckList := make([]int, 0)
	for _, baselineId := range baselineIdList {

		// 检查项筛选
		var baselineInfo BaselineInfo
		err := baselineCol.FindOne(c, bson.M{"baseline_id": baselineId}).Decode(&baselineInfo)
		if err != nil {
			ylog.Infof("Find error", err.Error())
		}
		if len(checkRequest.CheckList) == 0 {
			baselineCheckList = baselineInfo.CheckIdList
		} else {
			baselineCheckList = checkRequest.CheckList
		}

		// 获取符合条件的agent列表
		agentList := getBaselineAgentList(checkRequest.HostList, baselineInfo)

		// 基线任务下发
		taskResList := make([]taskResp, 0)

		if baselineId == WeakPassBaseline {
			// 弱口令基线任务下发
			taskMsg := def.AgentTaskMsg{
				Name:     "collector",
				DataType: WeakPassDataType,
			}

			taskResList, err = SendBaselineTask(agentList, checkRequest.User, taskMsg)

			// 将弱口令数据置为false
			agentIdList := make([]string, 0)
			for _, taskRes := range taskResList {
				agentIdList = append(agentIdList, taskRes.ID)
			}

			weakPassWrite := make([]mongo.WriteModel, len(agentIdList))
			for _, agentId := range agentIdList {
				agentInfo := dbtask.AgentInfoSearch(agentId)
				weakPassAgentBaseline.AgentId = agentId
				weakPassAgentBaseline.Hostname = agentInfo.Hostname
				weakPassAgentBaseline.Tags = agentInfo.Tags
				weakPassAgentBaseline.IntranetIpv4 = agentInfo.IntranetIpv4
				weakPassAgentBaseline.ExtranetIpv4 = agentInfo.ExtranetIpv4
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"agent_id": agentId, "baseline_id": WeakPassBaseline}).
					SetUpdate(bson.M{"$set": weakPassAgentBaseline}).SetUpsert(true)
				weakPassWrite = append(checkTaskWrite, model)
			}
			_, err := agentBaseCol.BulkWrite(c, weakPassWrite, writeOption)
			if err != nil {
				ylog.Errorf("BulkWrite error", err.Error())
			}
		} else {
			taskData, _ := json.Marshal(struct {
				BaselineID      int    `json:"baseline_id"`
				BaseLineVersion string `json:"baseline_version"`
				CheckIdList     []int  `json:"check_id_list"`
			}{
				BaselineID:      baselineId,
				BaseLineVersion: DefaultBaseLineVersion,
				CheckIdList:     baselineCheckList,
			})

			taskMsg := def.AgentTaskMsg{
				Name:     "baseline",
				Data:     string(taskData),
				DataType: BaselineDataType,
			}
			taskResList, err = SendBaselineTask(agentList, checkRequest.User, taskMsg)
		}

		// 更新任务状态
		for _, taskRes := range taskResList {
			agentId := taskRes.ID
			var taskStatusUpdate bson.M
			var checkStatusUpdate bson.M
			if taskRes.Code != 0 {
				taskStatusUpdate = bson.M{"status": "error", "last_check_time": time.Now().Unix(), "msg": taskRes.Msg}
				checkStatusUpdate = bson.M{"task_status": "error", "update_time": time.Now().Unix(), "err_reason": taskRes.Msg}
			} else {
				taskStatusUpdate = bson.M{"status": "running", "last_check_time": time.Now().Unix(), "msg": ""}
				checkStatusUpdate = bson.M{"task_status": "running", "update_time": time.Now().Unix()}
			}
			if baselineId == WeakPassBaseline {
				taskStatusUpdate["high_risk_num"] = 0
				taskStatusUpdate["pass_num"] = 1
				agentInfo := dbtask.AgentInfoSearch(agentId)
				weakPassAgentBaseline.AgentId = agentId
				taskStatusUpdate["hostname"] = agentInfo.Hostname
				taskStatusUpdate["tags"] = agentInfo.Tags
				taskStatusUpdate["intranet_ipv4"] = agentInfo.IntranetIpv4
				taskStatusUpdate["extranet_ipv4"] = agentInfo.ExtranetIpv4
			}

			// 更新基线任务状态
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"agent_id": agentId, "baseline_id": baselineId}).
				SetUpdate(bson.M{"$set": taskStatusUpdate}).SetUpsert(true)
			taskStatusWrite = append(taskStatusWrite, model)

			// 更新检查项任务状态
			for _, checkId := range baselineCheckList {
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"agent_id": agentId, "baseline_id": baselineId, "check_id": checkId}).
					SetUpdate(bson.M{"$set": checkStatusUpdate}).SetUpsert(true)
				checkTaskWrite = append(checkTaskWrite, model)
			}
		}

		// 更新基线检测状态
		if len(checkRequest.HostList) == 0 {
			baselineStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineStatus)
			_, err := baselineStatusCol.UpdateOne(c, bson.M{"baseline_id": baselineId},
				bson.M{"$set": bson.M{"status": "running", "last_check_time": time.Now().Unix()}})
			if err != nil {
				ylog.Errorf("Update error", err.Error())
			}
		}

		// 更新检测状态
		if len(checkRequest.HostList) == 0 && checkRequest.BaselineId == 0 && checkRequest.GroupId != 0 {
			// 整个策略组检查
			groupStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupStatus)
			_, err := groupStatusCol.UpdateOne(c, bson.M{"group_id": checkRequest.GroupId},
				bson.M{"$set": bson.M{"status": "running", "last_check_time": time.Now().Unix()}})
			if err != nil {
				ylog.Errorf("Update error", err.Error())
			}
		}

		// 更新基线主机任务状态
		taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
		if len(taskStatusWrite) > 0 {
			_, err = taskStatusCol.BulkWrite(c, taskStatusWrite, writeOption)
			if err != nil {
				ylog.Errorf("StartCheckBaseline", err.Error())
			}
		}

		// 更新检查项任务状态
		if len(checkTaskWrite) > 0 {
			_, err = agentBaseCol.BulkWrite(c, checkTaskWrite, writeOption)
			if err != nil {
				ylog.Errorf("StartCheckBaseline", err.Error())
			}
		}

		// 更新检查项表任务状态
		if len(baselineCheckList) > 0 {
			_, err = checkInfoCol.UpdateMany(c,
				bson.M{"baseline_id": baselineId, "check_id": bson.M{"$in": baselineCheckList}},
				bson.M{"$set": bson.M{"status": "running", "update_time": time.Now().Unix()}})
			if err != nil {
				ylog.Errorf("StartCheckBaseline", err.Error())
			}
		}
	}

	// 开启协程跟踪任务结束状态
	go judgeTaskTimeout("crontab")

	// 让mongo主从数据库同步，确保任务运行状态写入mongo从库
	endTime := time.Now().UnixNano()
	if (endTime - startTime) < int64(2*time.Second) {
		time.Sleep(1 * time.Second)
	}
	return
}

// 获取符合该baseline下发条件的agent列表
func getBaselineAgentList(beforeAgentList []string, baselineInfo BaselineInfo) (agentList []string) {
	c := context.Background()
	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	appCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintAppCollection)

	type AgentStruct struct {
		AgentId string `json:"agent_id" bson:"agent_id"`
	}

	if baselineInfo.BaselineId != 6000 {
		// 获取符合条件的agent列表
		searchFilter := make(map[string]interface{})
		if len(beforeAgentList) != 0 {
			searchFilter["agent_id"] = common.MongoInside{Inside: beforeAgentList}
		}
		searchFilter["last_heartbeat_time"] = bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}
		searchFilter["platform"] = common.MongoInside{Inside: baselineInfo.SystemList}
		findOption := options.Find().SetProjection(bson.M{"agent_id": 1})
		cursor, _ := hbCol.Find(c, searchFilter, findOption)

		var agentStructList []AgentStruct
		err := cursor.All(c, &agentStructList)
		if err != nil {
			return
		}
		for _, agentInfo := range agentStructList {
			agentList = append(agentList, agentInfo.AgentId)
		}
		return
	} else {
		// 容器基线下发
		cur, _ := appCol.Find(c, bson.M{"name": "kubelet"})
		for cur.Next(c) {
			var agentStruct AgentStruct
			err := cur.Decode(&agentStruct)
			if err != nil {
				return nil
			}
			agentList = append(agentList, agentStruct.AgentId)
		}
		return
	}
}
