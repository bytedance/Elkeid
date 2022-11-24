package v6

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/container"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/baseline"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/gin-gonic/gin"
	"github.com/muesli/cache2go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AgentBaseline struct {
	AgentId  string                `json:"agent_id" bson:"agent_id"`
	Data     baseline.BaselineInfo `json:"data" bson:"data"`
	DataType string                `json:"data_type" bson:"data_type"`
}

// 基线检查项详情
type BaselineCheckInfo struct {
	BaselineId    int    `json:"baseline_id" bson:"baseline_id"`
	CheckId       int    `json:"check_id" bson:"check_id"`
	BaselineCheck string `json:"baseline_check" bson:"baseline_check"`
	Type          string `json:"type" bson:"type"`
	Title         string `json:"title" bson:"title"`
	Description   string `json:"description" bson:"description"`
	Solution      string `json:"solution" bson:"solution"`
	Security      string `json:"security" bson:"security"`
	TitleCn       string `json:"title_cn" bson:"title_cn"`
	TypeCn        string `json:"type_cn" bson:"type_cn"`
	DescriptionCn string `json:"description_cn" bson:"description_cn"`
	SolutionCn    string `json:"solution_cn" bson:"solution_cn"`
	UpdateTime    int64  `json:"update_time" bson:"update_time"`
	PassRate      int    `json:"pass_rate" bson:"pass_rate"`
	Status        string `json:"status" bson:"status"`
}

var (
	weakPassTaskStatusCache *cache2go.CacheTable
)

func init() {
	weakPassTaskStatusCache = cache2go.Cache("weakPassTaskStatusCache")
}

// 获取弱口令数据(hub调用),datatype:5052
func SendWeakPassData(c *gin.Context) {
	type WeakPassResp struct {
		AgentId             string `json:"agent_id" bson:"agent_id"`
		WeakPassword        string `json:"weak_password" bson:"weak_password"`
		Username            string `json:"username" bson:"username"`
		Password            string `json:"password" bson:"password"`
		WeakPasswordContent string `json:"weak_password_content" bson:"weak_password_content"`
	}

	var weakPassResp WeakPassResp
	err := c.BindJSON(&weakPassResp)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 将弱口令结果转换为常规基线结果格式
	var agentBaselineInfo AgentBaseline
	agentBaselineInfo.AgentId = weakPassResp.AgentId
	var baselineInfo baseline.BaselineInfo

	baselineInfo.BaselineId = baseline.WeakPassBaseline
	baselineInfo.BaselineVersion = "1.0"
	baselineInfo.Status = "success"
	var checkInfo baseline.CheckInfo

	if weakPassResp.WeakPassword == "true" {
		checkInfo = baseline.CheckInfo{
			CheckId:       1,
			Security:      "high",
			Type:          "WeakPassword",
			Title:         "System login weak password detection",
			Description:   "Check if the system login is a weak password.",
			Solution:      "Change the password used for system login, it is recommended to use uppercase and lowercase + special character passwords.",
			TypeCn:        "弱口令",
			TitleCn:       "系统登录弱口令检测",
			DescriptionCn: "检查系统登录是否为弱口令。",
			SolutionCn:    "更改系统登录所使用的的口令，建议使用大小写+特殊字符的密码。",
			Result:        2,
		}
		checkInfo.Description += "\nUserName： " + weakPassResp.Username + "\nPassWord： " + weakPassResp.WeakPasswordContent
		checkInfo.DescriptionCn += "\n用户名： " + weakPassResp.Username + "\n密码： " + weakPassResp.WeakPasswordContent
	} else {
		_, err := weakPassTaskStatusCache.Value(weakPassResp.AgentId)
		if err != nil {
			// 更新基线主机任务状态
			taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
			_, err := taskStatusCol.UpdateOne(c,
				bson.M{"agent_id": weakPassResp.AgentId, "baseline_id": baselineInfo.BaselineId},
				bson.M{"$set": bson.M{"status": "finished"}})
			if err != nil {
				ylog.Errorf("update error", err.Error())
			}
			agentBaselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
			_, err = agentBaselineCol.UpdateOne(c,
				bson.M{"agent_id": weakPassResp.AgentId, "baseline_id": baselineInfo.BaselineId},
				bson.M{"$set": bson.M{"task_status": "finished"}})
			if err != nil {
				ylog.Errorf("update error", err.Error())
			}
			weakPassTaskStatusCache.Add(weakPassResp.AgentId, 1*time.Minute, "true")
		}
		return
	}
	baselineInfo.CheckList = append(baselineInfo.CheckList, checkInfo)
	agentBaselineInfo.Data = baselineInfo
	dbtask.LeaderBaselineAsyncWrite(agentBaselineInfo)
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// 获取基线数据信息(hub调用)
func SendBaselineData(c *gin.Context) {
	var newAsset map[string]interface{}
	err := c.BindJSON(&newAsset)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 反序列化data字段
	var baselineInfo baseline.BaselineInfo
	if data, ok := newAsset["data"]; ok {
		if sData, ok := data.(string); ok {
			err := json.Unmarshal([]byte(sData), &baselineInfo)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
		}
	}

	// 绑定agent基线列表
	var agentBaselineInfo AgentBaseline
	agentBaselineInfo.AgentId = newAsset["agent_id"].(string)
	agentBaselineInfo.Data = baselineInfo

	dbtask.LeaderBaselineAsyncWrite(agentBaselineInfo)
	common.CreateResponse(c, common.SuccessCode, "ok")
	return
}

// 获取策略组列表
func GetGroupList(c *gin.Context) {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)

	cur, err := collection.Find(c, bson.M{})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	groupList := make([]baseline.GroupInfo, 0)
	err = cur.All(c, &groupList)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	if c.Request.Header.Get(HeaderLang) == LangEN {
		for i, groupInfo := range groupList {
			groupList[i].GroupName = groupInfo.GroupNameEn
		}
	}

	// 将group_id=1放在首位
	newgroupList := make([]baseline.GroupInfo, 0)
	for _, groupInfo := range groupList {
		if groupInfo.GroupId == 1 {
			newgroupList = append(newgroupList, groupInfo)
		}
	}
	for _, groupInfo := range groupList {
		if groupInfo.GroupId != 1 {
			newgroupList = append(newgroupList, groupInfo)
		}
	}

	common.CreateResponse(c, common.SuccessCode, newgroupList)
}

// 开始基线检查
func Detect(c *gin.Context) {
	type Request struct {
		GroupId    int      `json:"group_id" bson:"group_id"`
		BaselineId int      `json:"baseline_id" bson:"baseline_id"`
		HostList   []string `json:"host_list" bson:"host_list"`
		IfAllHost  bool     `json:"if_all_host" bson:"if_all_host"`
		CheckList  []int    `json:"check_list" bson:"check_list"`
	}
	type Response struct {
		Status string `json:"status"`
	}
	var response Response
	response.Status = baseline.StatusFailed

	// 绑定筛选数据
	var request Request
	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, response)
		return
	}

	// 获取待检查主机列表
	if request.IfAllHost {
		request.HostList = make([]string, 0)
	}

	// 获取用户
	user, userOk := c.Get("user")
	if !userOk {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user info")
		return
	}
	userName, unOk := user.(string)
	if !unOk {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user name")
		return
	}

	// 开始检查
	checkRequest := baseline.CheckRequest{
		GroupId:    request.GroupId,
		BaselineId: request.BaselineId,
		HostList:   request.HostList,
		CheckList:  request.CheckList,
		User:       userName,
	}
	err = baseline.StartCheck(checkRequest)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}

	response.Status = baseline.StatusSuccess
	common.CreateResponse(c, common.SuccessCode, response)
	return
}

// 获取策略组统计信息
func GroupStatistics(c *gin.Context) {
	type Request struct {
		GroupId    int    `form:"group_id"`
		AgentId    string `form:"agent_id"`
		BaselineId int    `form:"baseline_id"`
	}
	var request Request
	err := c.BindQuery(&request)
	if err != nil {
		ylog.Errorf("GroupStatistics", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	var response baseline.CalcuBaselineStatisticRes

	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)

	if request.BaselineId != 0 {
		// 判断基线运行状态
		res := taskStatusCol.FindOne(c, bson.M{"baseline_id": request.BaselineId, "status": "running"})
		if res.Err() == nil {
			response.Status = "running"
		} else {
			response.Status = "finished"
		}

		if _, ok := baseline.BaselineStatisticMap[request.BaselineId]; ok {
			response = baseline.BaselineStatisticMap[request.BaselineId]
		}
		common.CreateResponse(c, common.SuccessCode, response)
		return
	}

	if request.GroupId != 0 {
		// 获取group的baseline列表
		var groupInfo baseline.GroupInfo
		baselineList := make([]int, 0)
		err := groupCol.FindOne(context.Background(), bson.M{"group_id": request.GroupId}).Decode(&groupInfo)
		if err != nil {
			ylog.Infof("Decode error", err.Error())
		}
		for _, baselineInfo := range groupInfo.BaselineList {
			baselineList = append(baselineList, baselineInfo.BaselineId)
		}

		// 判断策略组运行状态
		res := taskStatusCol.FindOne(c, bson.M{"baseline_id": bson.M{"$in": baselineList}, "status": "running"})
		if res.Err() == nil {
			response.Status = "running"
		} else {
			response.Status = "finished"
		}

		if _, ok := baseline.BaselineStatisticMap[request.GroupId]; ok {
			response = baseline.BaselineStatisticMap[request.GroupId]
		}
		common.CreateResponse(c, common.SuccessCode, response)
		return
	}

	if request.AgentId != "" {

		// 检查项以及通过率
		cur, _ := agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"agent_id": request.AgentId, "if_white": false, "status": baseline.StatusFailed}},
			bson.M{"$group": bson.M{"_id": "$check_id"}},
			bson.M{"$count": "count"},
		})
		if cur.TryNext(c) {
			cur.Next(c)
			response.RiskNum = cur.Current.Lookup("count").AsInt64()
		}

		// 检查项以及通过率
		cur, _ = agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"agent_id": request.AgentId}},
			bson.M{"$group": bson.M{"_id": "$check_id"}},
			bson.M{"$count": "count"},
		})
		if cur.TryNext(c) {
			cur.Next(c)
			response.ChecklistNum = cur.Current.Lookup("count").AsInt64()
		}
		if response.ChecklistNum != 0 {
			response.PassRate = 100 - int(response.RiskNum*100/response.ChecklistNum)
		}
		common.CreateResponse(c, common.SuccessCode, response)
		return
	}
	common.CreateResponse(c, common.ParamInvalidErrorCode, "need group/baseline/agent_id")
	return
}

// 策略组检查状态
func GroupCheckStatus(c *gin.Context) {
	type Request struct {
		GroupId    int `form:"group_id"`
		BaselineId int `form:"baseline_id"`
	}
	var request Request

	type Response struct {
		Status        string `json:"status"`
		Progress      int64  `json:"progress"`
		LastCheckTime int64  `json:"last_check_time"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindQuery(&request)
	if err != nil {
		ylog.Errorf("GroupStatistics", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)

	// 查看基线状态
	if request.BaselineId != 0 {
		baselineStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineStatus)
		var baselineStatus baseline.BaselineStatus
		err := baselineStatusCol.FindOne(context.Background(), bson.M{"baseline_id": request.BaselineId}).Decode(&baselineStatus)
		if err != nil {
			ylog.Infof("Decode error", err.Error())
		}

		// 获取最近检查时间
		todayUnix := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 1, 30, 0, 0, time.Now().Location()).Unix()
		if baselineStatus.LastCheckTime > todayUnix || baselineStatus.LastCheckTime == 0 {
			response.LastCheckTime = baselineStatus.LastCheckTime
		} else {
			response.LastCheckTime = todayUnix
		}

		// 判断运行状态
		if baselineStatus.Status == "finished" {
			response.Status = "finished"
			response.Progress = 100
			_, err2 := baselineStatusCol.UpdateOne(c, bson.M{"baseline_id": request.BaselineId},
				bson.M{"$set": bson.M{"last_check_time": response.LastCheckTime, "status": "finished"}})
			if err2 != nil {
				ylog.Errorf("update error", err.Error())
			}
		} else {

			searchFilter := make(map[string]interface{})
			searchFilter["baseline_id"] = request.BaselineId
			searchFilter["status"] = "running"
			res := taskStatusCol.FindOne(c, searchFilter)
			if res.Err() == nil {
				response.Status = "running"
				runTotal, _ := taskStatusCol.CountDocuments(c, searchFilter)
				searchFilter["status"] = "finished"
				finishTotal, _ := taskStatusCol.CountDocuments(c, searchFilter)
				if runTotal == 0 {
					response.Progress = 100
				} else {
					response.Progress = 100 - runTotal*100/(runTotal+finishTotal)
				}
			} else {
				response.Status = "finished"
				response.Progress = 100
				_, err := baselineStatusCol.UpdateOne(c, bson.M{"baseline_id": request.BaselineId},
					bson.M{"$set": bson.M{"last_check_time": response.LastCheckTime, "status": "finished"}})
				if err != nil {
					ylog.Errorf("update error", err.Error())
				}
			}
		}

	} else {

		groupStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupStatus)

		// 获取group的baseline列表
		var baselineGroupStatus baseline.BaselineGroupStatus
		err := groupStatusCol.FindOne(context.Background(), bson.M{"group_id": request.GroupId}).Decode(&baselineGroupStatus)
		if err != nil {
			ylog.Infof("Decode error", err.Error())
		}
		baselineList := make([]int, 0)
		for _, baselineId := range baselineGroupStatus.BaselineList {
			baselineList = append(baselineList, baselineId)
		}

		// 获取最近检查时间
		todayUnix := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 1, 30, 0, 0, time.Now().Location()).Unix()

		if baselineGroupStatus.LastCheckTime > todayUnix || baselineGroupStatus.LastCheckTime == 0 {
			response.LastCheckTime = baselineGroupStatus.LastCheckTime
		} else {
			response.LastCheckTime = todayUnix
		}

		// 判断策略组运行状态
		if baselineGroupStatus.Status == "finished" {
			response.Status = "finished"
			response.Progress = 100
			_, err := groupStatusCol.UpdateOne(c, bson.M{"group_id": request.GroupId},
				bson.M{"$set": bson.M{"last_check_time": response.LastCheckTime, "status": "finished"}})
			if err != nil {
				ylog.Errorf("update error", err.Error())
			}
		} else {
			searchFilter := make(map[string]interface{})
			searchFilter["baseline_id"] = common.MongoInside{Inside: baselineList}
			searchFilter["status"] = "running"
			res := taskStatusCol.FindOne(c, searchFilter)
			if res.Err() == nil {
				response.Status = "running"
				runTotal, _ := taskStatusCol.CountDocuments(c, searchFilter)
				searchFilter["status"] = "finished"
				finishTotal, _ := taskStatusCol.CountDocuments(c, searchFilter)
				if runTotal == 0 {
					response.Progress = 100
				} else {
					response.Progress = 100 - runTotal*100/(runTotal+finishTotal)
				}
			} else {
				response.Status = "finished"
				response.Progress = 100
				_, err := groupStatusCol.UpdateOne(c, bson.M{"group_id": request.GroupId},
					bson.M{"$set": bson.M{"last_check_time": response.LastCheckTime, "status": "finished"}})
				if err != nil {
					ylog.Errorf("update error", err.Error())
				}
			}
		}
	}

	common.CreateResponse(c, common.SuccessCode, response)
}

// 基线检查进度详情
func DetectProgressDetail(c *gin.Context) {
	type Request struct {
		GroupId    int `json:"group_id" bson:"group_id"`
		BaselineId int `json:"baseline_id" bson:"baseline_id"`
	}
	var request Request

	type FailedHost struct {
		HostName     string `json:"host_name"`
		FailedReason string `json:"failed_reason"`
	}

	type Response struct {
		ProgresDetail struct {
			Progress int64 `json:"progress"`
			TimeLeft int64 `json:"time_left"`
		} `json:"progress_detail"`
		RiskNum struct {
			PassNum   int `json:"pass_num"`
			HighNum   int `json:"high_num"`
			MediumNum int `json:"medium_num"`
			LowNum    int `json:"low_num"`
			FailedNum int `json:"failed_num"`
		} `json:"risk_num"`
		HostNum struct {
			Total    int64 `json:"total"`
			Finished int64 `json:"finished"`
		} `json:"host_num"`
		HostDetail struct {
			FailedHost    []FailedHost `json:"failed_host"`
			DetectingHost []string     `json:"detecting_host"`
		} `json:"host_detail"`
		Status string `json:"status"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GroupStatistics", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	baselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
	taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
	agentBaselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

	// 获取group的baseline列表
	baselineMap := make(map[int]string)
	baselineList := make([]int, 0)
	if request.BaselineId != 0 {
		var baselineInfo baseline.BaselineInfo
		err := baselineCol.FindOne(context.Background(), bson.M{"baseline_id": request.BaselineId}).Decode(&baselineInfo)
		if err != nil {
			ylog.Infof("Find error", err.Error())
		}
		baselineList = append(baselineList, baselineInfo.BaselineId)
		baselineMap[baselineInfo.BaselineId] = baselineInfo.BaselineName
	} else {
		var groupInfo baseline.GroupInfo
		err := groupCol.FindOne(context.Background(), bson.M{"group_id": request.GroupId}).Decode(&groupInfo)
		if err != nil {
			ylog.Infof("Find error", err.Error())
		}
		for _, baselineInfo := range groupInfo.BaselineList {
			baselineList = append(baselineList, baselineInfo.BaselineId)
			baselineMap[baselineInfo.BaselineId] = baselineInfo.BaselineName
		}
	}

	// 获取检查状态
	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = common.MongoInside{Inside: baselineList}
	searchFilter["status"] = "running"
	res := taskStatusCol.FindOne(c, searchFilter)
	if res.Err() == nil {
		response.Status = "running"
	} else {
		response.Status = "finished"
	}

	// 进度信息，主机数量统计: ProgresDetail，HostNum
	if response.Status == "running" {
		searchFilter = make(map[string]interface{})
		searchFilter["baseline_id"] = common.MongoInside{Inside: baselineList}
		response.Status = "running"
		total, _ := taskStatusCol.CountDocuments(c, searchFilter)
		searchFilter["status"] = "running"
		runTotal, _ := taskStatusCol.CountDocuments(c, searchFilter)
		finishedTotal := total - runTotal
		response.ProgresDetail.Progress = finishedTotal * 100 / total
		response.ProgresDetail.TimeLeft = runTotal/100 + 1
		response.HostNum.Total = total
		response.HostNum.Finished = finishedTotal
	}

	// 风险数量: RiskNum
	if response.Status == "finished" {
		searchFilter := make(map[string]interface{})
		searchFilter["baseline_id"] = common.MongoInside{Inside: baselineList}
		searchFilter["if_white"] = false
		groupFilter := bson.M{"$group": bson.M{
			"_id":   "$status",
			"count": bson.M{"$sum": 1},
		}}
		aggregateSearchList := make(bson.A, 0)
		aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchFilter})
		aggregateSearchList = append(aggregateSearchList, groupFilter)
		cur, err := agentBaselineCol.Aggregate(context.Background(), aggregateSearchList)
		resStuct := struct {
			Id    string `bson:"_id"`
			Count int    `bson:"count"`
		}{}
		if err == nil {
			for cur.Next(c) {
				err = cur.Decode(&resStuct)
				if resStuct.Id == "failed" {
					response.RiskNum.HighNum = resStuct.Count // 默认所有基线漏洞都是高危，所以先使用简单的查询
				} else if resStuct.Id == "passed" {
					response.RiskNum.PassNum = resStuct.Count
				} else if resStuct.Id == "error" {
					response.RiskNum.FailedNum = resStuct.Count
				}
			}
		}
	}

	// 主机详情 HostDetail
	searchFilter = make(map[string]interface{})
	searchFilter["baseline_id"] = common.MongoInside{Inside: baselineList}
	var statusList []string
	statusList = append(statusList, "error")
	if response.Status == "running" {
		statusList = append(statusList, "running")
	}
	searchFilter["status"] = common.MongoInside{Inside: statusList}
	errorHostMap := make(map[string]bool, 0)

	aggregateSearchList := make(bson.A, 0)
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchFilter})
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from":         infra.AgentHeartBeatCollection,
		"localField":   "agent_id",
		"foreignField": "agent_id",
		"as":           "agent_info",
	}})
	aggregateSearchList = append(aggregateSearchList, bson.M{"$project": bson.M{
		"status":      1,
		"msg":         1,
		"baseline_id": 1,
		"hostname":    "$agent_info.hostname",
	}})

	errStruct := struct {
		HostName     string `json:"host_name"`
		FailedReason string `json:"failed_reason"`
	}{}
	type HostResponse struct {
		Status     string   `json:"status" bson:"status"`
		BaselineId int      `json:"baseline_id" bson:"baseline_id"`
		Msg        string   `json:"msg" bson:"msg"`
		HostName   []string `json:"host_name" bson:"hostname"`
	}
	hostResponseList := make([]HostResponse, 0)

	cur, _ := taskStatusCol.Aggregate(c, aggregateSearchList)

	_ = cur.All(c, &hostResponseList)
	response.HostDetail.DetectingHost = make([]string, 0)
	response.HostDetail.FailedHost = make([]FailedHost, 0)

	for _, hostResponse := range hostResponseList {
		var hostname string
		if len(hostResponse.HostName) > 0 {
			hostname = hostResponse.HostName[0]
		} else {
			hostname = "unknown"
		}
		if hostResponse.Status == "running" {
			hostnameInfo := hostname + "(" + baselineMap[hostResponse.BaselineId] + ")"
			response.HostDetail.DetectingHost = append(response.HostDetail.DetectingHost, hostnameInfo)
		} else if hostResponse.Status == "error" {
			if _, ok := errorHostMap[hostname]; !ok {
				errorHostMap[hostname] = false
				errStruct.HostName = hostname
				errStruct.FailedReason = hostResponse.Msg
				response.HostDetail.FailedHost = append(response.HostDetail.FailedHost, errStruct)
			}
		}
	}

	common.CreateResponse(c, common.SuccessCode, response)
}

// 获取基线列表
func GetBaselineList(c *gin.Context) {
	type Request struct {
		GroupId      int    `json:"group_id" bson:"group_id"`
		AgentId      string `json:"agent_id" bson:"agent_id"`
		BaselineName string `json:"baseline_name" bson:"baseline_name"`
		Status       string `json:"status" bson:"status"`
	}
	type ResponseData struct {
		BaselineId       int    `json:"baseline_id" bson:"baseline_id"`
		BaselineName     string `json:"baseline_name" bson:"baseline_name"`
		BaselineNameEn   string `json:"baseline_name_en" bson:"baseline_name_en"`
		CheckListNum     int    `json:"check_list_num" bson:"check_list_num"`
		AffectedHost     int    `json:"affected_host" bson:"affected_host"`
		LastDetectedTime int64  `json:"last_detected_time" bson:"last_detected_time"`
		DetectStatus     string `json:"detect_status" bson:"detect_status"`
		TaskSuccess      bool   `json:"task_success" bson:"task_success"`
		DetectProgress   int64  `json:"detect_progress" bson:"detect_progress"`
		RiskNum          struct {
			HighNum   int `json:"high_num" bson:"high_num"`
			MediumNum int `json:"medium_num" bson:"medium_num"`
			LowNum    int `json:"low_num" bson:"low_num"`
		} `json:"risk_num" bson:"risk_num"`
	}
	type Response struct {
		DetectStatus string         `json:"detect_status"`
		BaselineList []ResponseData `json:"baseline_list"`
	}
	var response Response

	ifHeaderEn := c.Request.Header.Get(HeaderLang) == LangEN
	// 绑定筛选数据
	var request Request
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetBaselineList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetBaselineList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: nil, Sorter: nil}
	if pageRequest.OrderKey == "risk_num" {
		pageSearch.Sorter = bson.D{bson.E{Key: "high_risk_num", Value: -1}, bson.E{Key: "medium_risk_num", Value: -1}}
	} else if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	baselineStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineStatus)
	agentBaselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	baselineTaskCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)

	// 获取baseline列表
	baselineList := make([]int, 0)
	if request.GroupId != 0 {
		var groupInfo baseline.GroupInfo
		err := groupCol.FindOne(c, bson.M{"group_id": request.GroupId}).Decode(&groupInfo)
		if err != nil {
			ylog.Infof("Find error", err.Error())
		}
		for _, baselineInfo := range groupInfo.BaselineList {
			baselineList = append(baselineList, baselineInfo.BaselineId)
		}
	} else if request.AgentId != "" {
		aggregateSearchList := bson.A{
			bson.M{"$match": bson.M{"agent_id": request.AgentId}},
			bson.M{"$group": bson.M{"_id": "$baseline_id"}},
		}
		cursor, err := agentBaselineCol.Aggregate(c, aggregateSearchList)
		if err != nil {
			ylog.Errorf("GroupStatistics", err.Error())
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		} else {
			for cursor.Next(c) {
				baselineId64, _ := cursor.Current.Lookup("_id").AsInt64OK()
				strInt64 := strconv.FormatInt(baselineId64, 10)
				baselineId, _ := strconv.Atoi(strInt64)
				baselineList = append(baselineList, baselineId)
			}
		}
	}

	// 拼接mongo查询语句
	aggregateSearchList := make(bson.A, 0)

	// baseline条件筛选
	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = common.MongoInside{Inside: baselineList}
	if request.BaselineName != "" {
		if ifHeaderEn {
			searchFilter["baseline_name_en"] = common.MongoRegex{Regex: request.BaselineName}
		} else {
			searchFilter["baseline_name"] = common.MongoRegex{Regex: request.BaselineName}
		}
	}
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchFilter})

	// 拼接基线对应的主机信息
	lookupMatch := bson.A{}
	lookupMatch = append(lookupMatch, bson.M{"$eq": bson.A{"$baseline_id", "$$baseline_id"}})
	lookupMatch = append(lookupMatch, bson.M{"$eq": bson.A{"$status", "finished"}})

	if request.AgentId != "" {
		lookupMatch = append(lookupMatch, bson.M{"$eq": bson.A{"$agent_id", request.AgentId}})
	}
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from": infra.BaselineTaskStatus,
		"let":  bson.M{"baseline_id": "$baseline_id"},
		"pipeline": bson.A{
			bson.M{
				"$match": bson.M{
					"$expr": bson.M{
						"$and": lookupMatch}},
			},
		},
		"as": "task_status",
	}})
	aggregateSearchList = append(aggregateSearchList, bson.M{"$unwind": bson.M{
		"path":                       "$task_status",
		"preserveNullAndEmptyArrays": true,
	}})

	aggregateSearchList = append(aggregateSearchList, bson.M{"$group": bson.M{
		"_id":                "$baseline_id",
		"baseline_id":        bson.M{"$first": "$baseline_id"},
		"baseline_name":      bson.M{"$first": "$baseline_name"},
		"baseline_name_en":   bson.M{"$first": "$baseline_name_en"},
		"checklist_num":      bson.M{"$first": "$check_num"},
		"last_detected_time": bson.M{"$first": "$last_check_time"},
		"status":             bson.M{"$first": "$status"},
		"agent_id_list":      bson.M{"$addToSet": "$task_status.agent_id"},
		"high_risk_num":      bson.M{"$max": "$task_status.high_risk_num"},
		"medium_risk_num":    bson.M{"$max": "$task_status.medium_risk_num"},
		"low_risk_num":       bson.M{"$max": "$task_status.low_risk_num"},
	}})

	// 判断是否有风险的条件
	if request.Status == "risk" {
		aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{"$or": bson.A{bson.M{"high_risk_num": bson.M{"$gt": 0}}, bson.M{"medium_risk_num": bson.M{"$gt": 0}}}}})
	}
	if request.Status == "unrisk" {
		aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{"high_risk_num": bson.M{"$type": 10}}})
	}

	// 计算影响主机数
	aggregateSearchList = append(aggregateSearchList, bson.M{"$project": bson.M{
		"baseline_id":        1,
		"baseline_name":      1,
		"baseline_name_en":   1,
		"checklist_num":      1,
		"last_detected_time": 1,
		"status":             1,
		"affected_host":      bson.M{"$size": "$agent_id_list"},
		"high_risk_num":      1,
		"medium_risk_num":    1,
		"low_risk_num":       1,
	}})

	response.DetectStatus = "finished"
	response.BaselineList = make([]ResponseData, 0)
	pageResponse, err := common.DBAggregatePaginate(
		baselineStatusCol,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			v := struct {
				BaselineId       int    `json:"baseline_id" bson:"baseline_id"`
				BaselineName     string `json:"baseline_name" bson:"baseline_name"`
				BaselineNameEn   string `json:"baseline_name_en" bson:"baseline_name_en"`
				ChecklistNum     int    `json:"checklist_num" bson:"checklist_num"`
				LastDetectedTime int64  `json:"last_detected_time" bson:"last_detected_time"`
				HighRiskNum      int    `json:"high_risk_num" bson:"high_risk_num"`
				MediumRiskNum    int    `json:"medium_risk_num" bson:"medium_risk_num"`
				LowRiskNum       int    `json:"low_risk_num" bson:"low_risk_num"`
				AffectedHost     int    `json:"affected_host" bson:"affected_host"`
				Status           string `json:"status" bson:"status"`
			}{}
			_ = cursor.Decode(&v)

			// 绑定基线数据
			var responseData ResponseData
			responseData.BaselineId = v.BaselineId
			responseData.CheckListNum = v.ChecklistNum
			responseData.AffectedHost = v.AffectedHost
			responseData.LastDetectedTime = v.LastDetectedTime
			responseData.RiskNum.HighNum = v.HighRiskNum
			responseData.RiskNum.MediumNum = v.MediumRiskNum
			responseData.RiskNum.LowNum = v.LowRiskNum
			if ifHeaderEn {
				responseData.BaselineName = v.BaselineNameEn
			} else {
				responseData.BaselineName = v.BaselineName
			}

			// 获取该基线运行状态

			// 获取group的baseline列表
			if request.AgentId != "" {
				var baselineTasksStatus baseline.BaselineTaskStatus
				err := baselineTaskCol.FindOne(context.Background(), bson.M{"baseline_id": v.BaselineId, "agent_id": request.AgentId}).Decode(&baselineTasksStatus)
				if err != nil {
					ylog.Infof("Find error", err.Error())
				}
				if baselineTasksStatus.Status == "running" {
					responseData.DetectStatus = "running"
					responseData.DetectProgress = 0
				} else {
					responseData.DetectStatus = "finished"
					responseData.DetectProgress = 1
				}
			} else {
				var baselineStatus baseline.BaselineStatus
				err := baselineStatusCol.FindOne(context.Background(), bson.M{"baseline_id": v.BaselineId}).Decode(&baselineStatus)
				if err != nil {
					ylog.Infof("Find error", err.Error())
				}
				if baselineStatus.Status == "finished" || v.Status == "finished" {
					responseData.DetectStatus = "finished"
					responseData.DetectProgress = 1
				} else {
					runningNum, _ := baselineTaskCol.CountDocuments(c, bson.M{
						"baseline_id": v.BaselineId,
						"status":      "running",
					})
					if runningNum != 0 {
						responseData.DetectStatus = "running"
						response.DetectStatus = "running"
						totalNum, _ := baselineTaskCol.CountDocuments(c, bson.M{"baseline_id": v.BaselineId})
						finishedNum := totalNum - runningNum
						responseData.DetectProgress = finishedNum * 100 / totalNum
					} else {
						responseData.DetectStatus = "finished"
						responseData.DetectProgress = 1
						_, err := baselineStatusCol.UpdateOne(c, bson.M{"baseline_id": v.BaselineId},
							bson.M{"$set": bson.M{"status": "finished"}})
						if err != nil {
							ylog.Errorf("update error", err.Error())
						}
					}
					if responseData.DetectStatus == "error" {
						responseData.TaskSuccess = false
					} else {
						responseData.TaskSuccess = true
					}
				}

				// 更新基线的上次检测时间
				todayUnix := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 1, 30, 0, 0, time.Now().Location()).Unix()

				if responseData.LastDetectedTime < todayUnix && responseData.LastDetectedTime != 0 {
					responseData.LastDetectedTime = todayUnix
				}
				_, err = baselineStatusCol.UpdateOne(c, bson.M{"baseline_id": v.BaselineId},
					bson.M{"$set": bson.M{"last_check_time": responseData.LastDetectedTime}})
				if err != nil {
					ylog.Errorf("update error", err.Error())
				}
			}

			response.BaselineList = append(response.BaselineList, responseData)
			return nil
		},
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, response, *pageResponse)
}

// 基线影响主机列表
func GetBaselineDetailList(c *gin.Context) {
	type Request struct {
		BaselineId int    `json:"baseline_id" bson:"baseline_id"`
		AgentId    string `json:"agent_id" bson:"agent_id"`
		Hostname   string `json:"hostname" bson:"hostname"`
	}
	var request Request
	type ResponseData struct {
		AgentId         string   `json:"agent_id" bson:"agent_id"`
		Hostname        string   `json:"hostname" bson:"hostname"`
		Tags            []string `json:"tags" bson:"tags"`
		IntrancetIp     string   `json:"intrancet_ip" bson:"intrancet_ip"`
		IntrancetIpList []string `json:"intrancet_ip_list" bson:"intrancet_ip_list"`
		ExtrancetIp     string   `json:"extrancet_ip" bson:"extrancet_ip"`
		DetectStatus    string   `json:"detect_status" bson:"detect_status"`
		PassNum         int      `json:"pass_num" bson:"pass_num"`
		ErrorDetail     string   `json:"error_detail" bson:"error_detail"`
		RiskNum         struct {
			HighNum   int `json:"high_num" bson:"high_num"`
			MediumNum int `json:"medium_num" bson:"medium_num"`
			LowNum    int `json:"low_num" bson:"low_num"`
		} `json:"risk_num" bson:"risk_num"`
		Region      string `json:"region" bson:"region"`
		NodeId      string `json:"node_id" bson:"node_id"`
		NodeName    string `json:"node_name" bson:"node_name"`
		NodeIp      string `json:"node_ip" bson:"node_ip"`
		ClusterId   string `json:"cluster_id" bson:"cluster_id"`
		ClusterName string `json:"cluster_name" bson:"cluster_name"`
	}
	type Response struct {
		DetectStatus string         `json:"detect_status"`
		BaselineInfo []ResponseData `json:"baseline_info"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetBaselineList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetBaselineList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: nil, Sorter: nil}

	pageSort := bson.D{}
	// 按照风险项排序
	if pageRequest.OrderKey == "risk_num" {
		pageSort = append(pageSort, bson.E{Key: "high_risk_num", Value: pageRequest.OrderValue})
		pageSort = append(pageSort, bson.E{Key: "medium_risk_num", Value: pageRequest.OrderValue})
		pageSort = append(pageSort, bson.E{Key: "low_risk_num", Value: pageRequest.OrderValue})
	} else if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSort = append(pageSort, bson.E{Key: pageRequest.OrderKey, Value: pageRequest.OrderValue})
	} else {
		pageSort = append(pageSort, bson.E{Key: "high_risk_num", Value: -1})
		pageSort = append(pageSort, bson.E{Key: "medium_risk_num", Value: -1})
		pageSort = append(pageSort, bson.E{Key: "low_risk_num", Value: -1})
	}
	pageSort = append(pageSort, bson.E{Key: "detect_status", Value: 1})
	pageSort = append(pageSort, bson.E{Key: "_id", Value: 1})
	pageSearch.Sorter = pageSort

	// 获取主机信息
	baseTaskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = request.BaselineId
	if request.AgentId != "" {
		searchFilter["agent_id"] = request.AgentId
	}
	if request.Hostname != "" {
		searchFilter["hostname"] = common.MongoRegex{Regex: request.Hostname}
	}
	pageSearch.Filter = searchFilter

	ipList := make([]string, 0)
	pageResponse, err := common.DBSearchPaginate(
		baseTaskStatusCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var v baseline.BaselineTaskStatus
			err := cursor.Decode(&v)
			if err != nil {
				ylog.Infof("Decode error", err.Error())
			}

			// 绑定返回数据
			var responseData ResponseData
			responseData.AgentId = v.AgentId
			responseData.Hostname = v.Hostname
			responseData.Tags = v.Tags
			if len(v.IntranetIpv4) != 0 {
				responseData.IntrancetIpList = v.IntranetIpv4
				responseData.IntrancetIp = v.IntranetIpv4[0]
				for _, ip := range v.IntranetIpv4 {
					ipList = append(ipList, ip)
				}
			}
			if len(v.ExtranetIpv4) != 0 {
				responseData.ExtrancetIp = v.ExtranetIpv4[0]
			}
			responseData.DetectStatus = v.Status
			responseData.ErrorDetail = v.Msg
			if responseData.DetectStatus == "running" {
				response.DetectStatus = "running"
			}

			responseData.PassNum = v.PassNum
			responseData.RiskNum.HighNum = v.HighRiskNum
			responseData.RiskNum.MediumNum = v.MediumRiskNum
			responseData.RiskNum.LowNum = v.LowRiskNum

			response.BaselineInfo = append(response.BaselineInfo, responseData)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetBaselineDetailList", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 添加容器信息
	if request.BaselineId == 6000 {
		ipNodeList := getContainerInfoByIpList(ipList)
		for i, baselineInfo := range response.BaselineInfo {
			for _, ip := range baselineInfo.IntrancetIpList {
				if nodeInfo, ok := ipNodeList[ip]; ok {
					response.BaselineInfo[i].NodeId = nodeInfo.NodeId
					response.BaselineInfo[i].NodeName = nodeInfo.NodeName
					response.BaselineInfo[i].NodeIp = nodeInfo.IntranetIp
					response.BaselineInfo[i].Region = nodeInfo.ClusterRegion
					response.BaselineInfo[i].ClusterName = nodeInfo.ClusterName
					response.BaselineInfo[i].ClusterId = nodeInfo.ClusterId
				}
			}
		}
	}

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, response, *pageResponse)
}

// 检查结果列表
func GetCheckResList(c *gin.Context) {
	type Request struct {
		BaselineId    int    `json:"baseline_id" bson:"baseline_id"`
		AgentId       string `json:"agent_id" bson:"agent_id"`
		ChecklistName string `json:"checklist_name" bson:"checklist_name"`
		Result        string `json:"result" bson:"result"`
	}
	var request Request
	type Response struct {
		ChecklistId     int64  `json:"checklist_id" bson:"checklist_id"`
		ChecklistName   string `json:"checklist_name" bson:"checklist_name"`
		Level           string `json:"level" bson:"level"`
		ChecklistStatus string `json:"checklist_status" bson:"checklist_status"`
		WhitelistStatus bool   `json:"whitelist_status" bson:"whitelist_status"`
		WhitelistDetail string `json:"whitelist_detail" bson:"whitelist_detail"`
		FailedDetail    string `json:"failed_detail" bson:"failed_detail"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetCheckResList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetCheckResList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = request.BaselineId
	searchFilter["agent_id"] = request.AgentId
	if request.ChecklistName != "" {
		searchFilter["check_name_cn"] = common.MongoRegex{Regex: request.ChecklistName}
	}
	if len(request.Result) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: request.Result}
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	pageSort := bson.D{bson.E{Key: "status", Value: 1}, bson.E{Key: "level", Value: 1}, bson.E{Key: "_id", Value: 1}}
	pageSearch.Sorter = pageSort

	// 获取检测结果
	agentBaselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

	// 聚合查询
	dataResponse := make([]Response, 0)
	pageResponse, err := common.DBSearchPaginate(
		agentBaselineCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var agentBaseline baseline.AgentBaselineInfo
			err := cursor.Decode(&agentBaseline)
			if err != nil {
				ylog.Infof("Decode error", err.Error())
			}
			response = Response{
				ChecklistId:     agentBaseline.CheckId,
				ChecklistName:   agentBaseline.CheckNameCn,
				Level:           agentBaseline.CheckLevel,
				ChecklistStatus: agentBaseline.Status,
				WhitelistStatus: agentBaseline.IfWhite,
				WhitelistDetail: agentBaseline.WhiteReason,
				FailedDetail:    agentBaseline.ErrReason,
			}
			dataResponse = append(dataResponse, response)
			return nil
		},
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 基线对应检查项列表
func GetBaselineCheckList(c *gin.Context) {
	type Request struct {
		BaselineId int    `json:"baseline_id" bson:"baseline_id"`
		CheckName  string `json:"check_name" bson:"check_name"`
	}
	var request Request
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetBaselineCheckList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetBaselineCheckList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = request.BaselineId
	if request.CheckName != "" {
		searchFilter["title_cn"] = common.MongoRegex{Regex: request.CheckName}
	}

	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	type Response struct {
		DetectStatus string              `json:"detect_status"`
		BaselineInfo []BaselineCheckInfo `json:"baseline_info"`
	}
	var response Response
	response.DetectStatus = "finished"

	checkInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineCheckInfoColl)

	go baseline.SetBaselineCheckTask(request.BaselineId, "once") // 计算检查通过率

	pageResponse, err := common.DBSearchPaginate(
		checkInfoCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var baselineCheckInfo BaselineCheckInfo
			err := cursor.Decode(&baselineCheckInfo)
			if err != nil {
				ylog.Errorf("GetBaselineCheckList", err.Error())
				return err
			}

			if c.Request.Header.Get(HeaderLang) == LangCN {
				baselineCheckInfo.Solution = baselineCheckInfo.SolutionCn
				baselineCheckInfo.Description = baselineCheckInfo.DescriptionCn
				baselineCheckInfo.Type = baselineCheckInfo.TypeCn
				baselineCheckInfo.Title = baselineCheckInfo.TitleCn
			}
			if baselineCheckInfo.Status == "running" && response.DetectStatus == "finished" {
				response.DetectStatus = "running"
			}
			response.BaselineInfo = append(response.BaselineInfo, baselineCheckInfo)
			return nil
		},
	)

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, response, *pageResponse)
}

// 检查项影响主机列表
func GetCheckHostList(c *gin.Context) {
	type Request struct {
		BaselineId int      `json:"baseline_id" bson:"baseline_id"`
		CheckId    int      `json:"check_id" bson:"check_id"`
		AgentId    string   `json:"agent_id" bson:"agent_id"`
		Hostname   string   `json:"hostname" bson:"hostname"`
		Result     []string `json:"result" bson:"result"`
		Tag        []string `json:"tag" bson:"tag"`
		Ip         []string `json:"ip" bson:"ip"`
	}
	var request Request
	type ResponseData struct {
		AgentId         string   `json:"agent_id" bson:"agent_id"`
		Hostname        string   `json:"hostname" bson:"hostname"`
		IntrancetIp     string   `json:"intrancet_ip" bson:"intrancet_ip"`
		IntrancetIpList []string `json:"intrancet_ip_list" bson:"intrancet_ip_list"`
		ExtrancetIp     string   `json:"extrancet_ip" bson:"extrancet_ip"`
		DetectStatus    string   `json:"detect_status" bson:"detect_status"`
		Tag             []string `json:"tag" bson:"tag"`
		Result          string   `json:"result" bson:"result"`
		WhitelistStatus bool     `json:"whitelist_status" bson:"whitelist_status"`
		FailedDetail    string   `json:"failed_detail" bson:"failed_detail"`
		Region          string   `json:"region" bson:"region"`
		NodeId          string   `json:"node_id" bson:"node_id"`
		NodeName        string   `json:"node_name" bson:"node_name"`
		NodeIp          string   `json:"node_ip" bson:"node_ip"`
		ClusterId       string   `json:"cluster_id" bson:"cluster_id"`
		ClusterName     string   `json:"cluster_name" bson:"cluster_name"`
	}
	type Response struct {
		DetectStatus string         `json:"detect_status"`
		BaselineInfo []ResponseData `json:"baseline_info"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetCheckHostList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetCheckHostList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: nil, Sorter: nil}

	pageSort := bson.D{}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSort = append(pageSort, bson.E{Key: pageRequest.OrderKey, Value: pageRequest.OrderValue})
	}
	pageSort = append(pageSort, bson.E{Key: "err_reason", Value: 1})
	pageSort = append(pageSort, bson.E{Key: "status", Value: 1})
	pageSort = append(pageSort, bson.E{Key: "if_white", Value: 1})
	pageSort = append(pageSort, bson.E{Key: "_id", Value: 1})
	pageSearch.Sorter = pageSort

	agentBaselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

	// 获取主机信息
	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = request.BaselineId
	searchFilter["check_id"] = request.CheckId
	if request.AgentId != "" {
		searchFilter["agent_id"] = request.AgentId
	}
	if len(request.Result) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: request.Result}
	}
	pageSearch.Filter = searchFilter

	ipList := make([]string, 0)
	pageResponse, err := common.DBSearchPaginate(
		agentBaselineCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var v baseline.AgentBaselineInfo
			_ = cursor.Decode(&v)

			// 绑定返回数据
			var responseData ResponseData
			responseData.AgentId = v.AgentId
			responseData.Hostname = v.Hostname
			responseData.Tag = v.Tags
			if len(v.IntranetIpv4) != 0 {
				responseData.IntrancetIpList = v.IntranetIpv4
				responseData.IntrancetIp = v.IntranetIpv4[0]
				for _, ip := range v.IntranetIpv4 {
					ipList = append(ipList, ip)
				}
			}
			if len(v.ExtranetIpv4) != 0 {
				responseData.ExtrancetIp = v.ExtranetIpv4[0]
			}
			responseData.DetectStatus = v.TaskStatus
			if responseData.DetectStatus == "running" {
				response.DetectStatus = "running"
			}

			// 获取加白状态
			responseData.WhitelistStatus = v.IfWhite
			responseData.FailedDetail = v.ErrReason
			responseData.Result = v.Status

			response.BaselineInfo = append(response.BaselineInfo, responseData)
			return nil
		},
	)

	// 添加容器信息
	if request.BaselineId == 6000 {
		ipNodeList := getContainerInfoByIpList(ipList)
		for i, baselineInfo := range response.BaselineInfo {
			for _, ip := range baselineInfo.IntrancetIpList {
				if nodeInfo, ok := ipNodeList[ip]; ok {
					response.BaselineInfo[i].NodeId = nodeInfo.NodeId
					response.BaselineInfo[i].NodeName = nodeInfo.NodeName
					response.BaselineInfo[i].NodeIp = nodeInfo.IntranetIp
					response.BaselineInfo[i].Region = nodeInfo.ClusterRegion
					response.BaselineInfo[i].ClusterName = nodeInfo.ClusterName
					response.BaselineInfo[i].ClusterId = nodeInfo.ClusterId
				}
			}
		}
	}

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, response, *pageResponse)
}

// 获取一个检查项详情
func GetChecklistDetail(c *gin.Context) {
	type Request struct {
		AgentId     string `json:"agent_id" bson:"agent_id"`
		BaselineId  int    `json:"baseline_id" bson:"baseline_id"`
		ChecklistId int    `json:"checklist_id" bson:"checklist_id"`
	}
	var request Request
	type Response struct {
		Type          string `json:"type" bson:"type"`
		Level         string `json:"level" bson:"check_level"`
		Name          string `json:"name" bson:"check_name"`
		NameCn        string `json:"name_cn" bson:"check_name_cn"`
		Description   string `json:"description" bson:"description"`
		DescriptionCn string `json:"description_cn" bson:"description_cn"`
		Resolve       string `json:"resolve" bson:"solution"`
		ResolveCn     string `json:"resolve_cn" bson:"solution_cn"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetChecklistDetail", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	searchFilter := make(map[string]interface{})

	searchFilter["agent_id"] = request.AgentId
	searchFilter["baseline_id"] = request.BaselineId
	searchFilter["check_id"] = request.ChecklistId
	err = agentBaseCol.FindOne(c, searchFilter).Decode(&response)

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	if c.Request.Header.Get(HeaderLang) == LangCN {
		response.Name = response.NameCn
		response.Description = response.DescriptionCn
		response.Resolve = response.ResolveCn
	}
	CreateResponse(c, common.SuccessCode, response)
}

// 获取白名单弹框主机数
func GetWhiteHostNum(c *gin.Context) {
	type Request struct {
		BaselineId  int  `json:"baseline_id" bson:"baseline_id"`
		ChecklistId int  `json:"checklist_id" bson:"check_id"`
		IfWhiten    bool `json:"if_whiten" bson:"if_white"`
	}
	var request Request

	type Response struct {
		HostNum int64 `json:"host_num"`
	}
	var response Response
	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetCheckResList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, response)
		return
	}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

	// 拼接过滤项
	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = request.BaselineId
	searchFilter["check_id"] = request.ChecklistId
	searchFilter["if_white"] = request.IfWhiten
	if request.IfWhiten == false {
		searchFilter["status"] = "failed"
	}

	response.HostNum, err = collection.CountDocuments(c, searchFilter)

	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, response)
}

// 重新计算baselineTaskStatus 表某基线统计数据
func setBaselineTaskStatus(baselineId int) {
	c := context.Background()
	myFunc := func() {
		baselineTaskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
		agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

		cur, _ := agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": baselineId, "status": baseline.StatusFailed}},
			bson.M{"$group": bson.M{"_id": bson.M{"agent_id": "$agent_id", "check_level": "$check_level", "if_white": "$if_white"},
				"agent_id":    bson.M{"$first": "$agent_id"},
				"check_level": bson.M{"$first": "$check_level"},
				"if_white":    bson.M{"$first": "$if_white"},
				"total":       bson.M{"$sum": 1}}},
		})

		type UpdateStruct struct {
			HighRiskNum   int `json:"high_risk_num" bson:"high_risk_num"`
			MediumRiskNum int `json:"medium_risk_num" bson:"medium_risk_num"`
			LowRiskNum    int `json:"low_risk_num" bson:"low_risk_num"`
		}

		agentUpdateMap := make(map[string]UpdateStruct, 0)

		taskStatusWrite := make([]mongo.WriteModel, 0)

		for cur.Next(c) {
			tmpS := struct {
				CheckLevel string `bson:"check_level"`
				AgentId    string `bson:"agent_id"`
				IfWhite    bool   `bson:"if_white"`
				Total      int    `bson:"total"`
			}{}
			err := cur.Decode(&tmpS)
			if err != nil {
				ylog.Infof("Decode error", err.Error())
			}

			var updateStruct UpdateStruct
			if _, ok := agentUpdateMap[tmpS.AgentId]; ok {
				updateStruct = agentUpdateMap[tmpS.AgentId]
			} else {
				agentUpdateMap[tmpS.AgentId] = updateStruct
			}
			if tmpS.IfWhite {
				continue
			}

			switch tmpS.CheckLevel {
			case baseline.BaselineCheckHigh:
				updateStruct.HighRiskNum = tmpS.Total
			case baseline.BaselineCheckMid:
				updateStruct.MediumRiskNum = tmpS.Total
			case baseline.BaselineCheckLow:
				updateStruct.LowRiskNum = tmpS.Total
			}
			agentUpdateMap[tmpS.AgentId] = updateStruct
		}
		for agentId, updateStruct := range agentUpdateMap {
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"agent_id": agentId, "baseline_id": baselineId}).
				SetUpdate(bson.M{"$set": updateStruct})
			taskStatusWrite = append(taskStatusWrite, model)
		}

		if len(taskStatusWrite) > 0 {
			writeOption := &options.BulkWriteOptions{}
			writeOption.SetOrdered(false)
			_, err := baselineTaskStatusCol.BulkWrite(c, taskStatusWrite, writeOption)
			if err != nil {
				ylog.Errorf("BulkWrite error", err.Error())
			}
		}
	}
	myFunc()
	time.Sleep(3 * time.Second)
	myFunc()
	time.Sleep(3 * time.Minute)
}

// 检查项加白
func ChecklistWhiten(c *gin.Context) {
	type Request struct {
		BaselineId      int      `json:"baseline_id" bson:"baseline_id"`
		ChecklistIdList []int    `json:"checklist_id_list" bson:"checklist_id_list"`
		IfWhiten        bool     `json:"if_whiten" bson:"if_white"`
		AgentIdList     []string `json:"agent_id_list" bson:"agent_id_list"`
		WhitelistDetail string   `json:"whitelist_detail" bson:"whitelist_detail"`
	}
	var request Request

	type Response struct {
		Status string `json:"status"`
	}
	var response Response
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetCheckResList", err.Error())
		response.Status = baseline.StatusFailed
		common.CreateResponse(c, common.ParamInvalidErrorCode, response)
		return
	}
	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

	searchFilter := make(map[string]interface{})
	searchFilter["baseline_id"] = request.BaselineId
	if len(request.ChecklistIdList) != 0 {
		searchFilter["check_id"] = common.MongoInside{Inside: request.ChecklistIdList}
	}
	if len(request.AgentIdList) != 0 {
		searchFilter["agent_id"] = common.MongoInside{Inside: request.AgentIdList}
	}

	_, err = agentBaseCol.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{
		"if_white":     request.IfWhiten,
		"white_reason": request.WhitelistDetail,
	}})
	if err != nil {
		ylog.Errorf("BulkWrite error", err.Error())
	}
	go setBaselineTaskStatus(request.BaselineId)
	time.Sleep(time.Second)

	response.Status = baseline.StatusSuccess
	common.CreateResponse(c, common.SuccessCode, response)
	return
}

// 获取基线漏洞统计信息
func GetBaselineStatistics(c *gin.Context) {
	type Response struct {
		Unprocessed int64 `json:"unprocessed" bson:"unprocessed"`
		Low         int64 `json:"low" bson:"low"`
		Mid         int64 `json:"mid" bson:"mid"`
		High        int64 `json:"high" bson:"high"`
	}
	var response Response

	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

	// 获取需要统计的基线列表
	var groupInfo baseline.GroupInfo
	BaselineDefaultList := make([]int, 0)
	err := groupCol.FindOne(context.Background(), bson.M{"group_id": 1}).Decode(&groupInfo)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	for _, baselineInfo := range groupInfo.BaselineList {
		BaselineDefaultList = append(BaselineDefaultList, baselineInfo.BaselineId)
	}

	cursor, err := agentBaseCol.Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"status":      "failed",
				"if_white":    false,
				"baseline_id": bson.M{"$in": BaselineDefaultList},
			},
		},
		bson.M{
			"$lookup": bson.M{
				"from": infra.BaselineCheckInfoColl,
				"let":  bson.M{"check_id": "$check_id", "baseline_id": "$baseline_id"},
				"pipeline": bson.A{
					bson.M{
						"$match": bson.M{
							"$expr": bson.M{
								"$and": bson.A{
									bson.M{"$eq": bson.A{"$check_id", "$$check_id"}},
									bson.M{"$eq": bson.A{"$baseline_id", "$$baseline_id"}},
								}}},
					},
				},
				"as": "check_info",
			},
		},
		bson.M{
			"$unwind": "$check_info",
		},
		bson.M{
			"$group": bson.M{
				"_id":   "$check_info.security",
				"count": bson.M{"$sum": 1},
			}},
	})

	if err != nil {
		ylog.Errorf("GetBaselineStatistics", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	for cursor.Next(c) {
		level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
		count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
		if ok1 && ok2 {
			switch level {
			case baseline.BaselineCheckHigh:
				response.High = count
				response.Unprocessed += count
			case baseline.BaselineCheckMid:
				response.Mid = count
			case baseline.BaselineCheckLow:
				response.Low = count
			}
		}
	}

	common.CreateResponse(c, common.SuccessCode, response)
}

// 导出基线数据
func GetBaselineDownload(c *gin.Context) {
	request := struct {
		IdList     []string `json:"id_list" bson:"id_list"`
		Conditions struct {
			BaselineId    int64  `json:"baseline_id" bson:"baseline_id"`
			AgentId       string `json:"agent_id" bson:"agent_id"`
			ChecklistName string `json:"checklist_name" bson:"checklist_name"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	searchFilter := make(map[string]interface{})
	searchFilter["agent_id"] = request.Conditions.AgentId
	searchFilter["baseline_id"] = request.Conditions.BaselineId
	searchFilter["check_name_cn"] = common.MongoRegex{Regex: request.Conditions.ChecklistName}
	cursor, err := agentBaseCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var exportList [][]string
	for cursor.Next(c) {
		var agentBaseline baseline.AgentBaselineInfo
		_ = cursor.Decode(&agentBaseline)

		exportData := make([]string, 0, 9)

		exportData = append(exportData, agentBaseline.AgentId)
		exportData = append(exportData, strconv.FormatInt(agentBaseline.BaselineId, 10))
		exportData = append(exportData, strconv.FormatInt(agentBaseline.CheckId, 10))
		exportData = append(exportData, agentBaseline.CheckName)
		exportData = append(exportData, agentBaseline.CheckNameCn)
		exportData = append(exportData, agentBaseline.Status)
		exportData = append(exportData, strconv.FormatBool(agentBaseline.IfWhite))
		exportData = append(exportData, agentBaseline.WhiteReason)
		exportData = append(exportData, agentBaseline.ErrReason)
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "agent_id", Header: "agent_id"},
		{Key: "baseline_id", Header: "baseline_id"},
		{Key: "check_id", Header: "check_id"},
		{Key: "check_name", Header: "check_name"},
		{Key: "check_name_cn", Header: "check_name_cn"},
		{Key: "status", Header: "status"},
		{Key: "if_white", Header: "if_white"},
		{Key: "white_reason", Header: "white_reason"},
		{Key: "err_reason", Header: "err_reason"},
	}

	filename := "baseline_infected" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 通过ip获取容器基线相关信息
func getContainerInfoByIpList(ipList []string) map[string]container.ClusterNodeInfo {
	c := context.Background()
	kubeNodeCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeNodeInfo)
	cur, _ := kubeNodeCol.Find(c, bson.M{"intranet_ip": bson.M{"$in": ipList}})

	ipNodeMap := make(map[string]container.ClusterNodeInfo, 0)
	for cur.Next(c) {
		var nodeInfo container.ClusterNodeInfo
		err := cur.Decode(&nodeInfo)
		if err != nil {
			ylog.Infof("Decode error", err.Error())
		}
		ipNodeMap[nodeInfo.IntranetIp] = nodeInfo
	}
	return ipNodeMap
}
