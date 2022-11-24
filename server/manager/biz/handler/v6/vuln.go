package v6

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/baseline"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/bytedance/Elkeid/server/manager/internal/vuln"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PkgInfo struct {
	AgentId       string `json:"agent_id" bson:"agent_id"`
	PackageSeq    string `json:"package_seq" bson:"package_seq"`
	Type          string `json:"type" bson:"type"`
	Token         string `json:"token" bson:"token"`
	Name          string `json:"name" bson:"name"`
	Version       string `json:"sversion" bson:"version"`
	Source        string `json:"source" bson:"source"`
	Status        string `json:"status" bson:"status"`
	Vendor        string `json:"vendor" bson:"vendor"`
	Cmdline       string `json:"cmdline" bson:"cmdline"`
	Pid           string `json:"pid" bson:"pid"`
	Path          string `json:"path" bson:"path"`
	ContainerName string `json:"container_name" bson:"container_name"`
	ContainerId   string `json:"container_id" bson:"container_id"`
}

const (
	HeaderLang = "Accept-Language"
	LangCN     = "zh-CN"
	LangEN     = "en-US"
)

func VulnInit() {
	go FlushPkgInfo()
}

// 获取agent软件包信息(hub调用)
var pkgMap = make(map[string][]PkgInfo)
var vulnMutex sync.Mutex

func GetAgentPkgList(c *gin.Context) {
	var pkgInfo PkgInfo

	err := c.BindJSON(&pkgInfo)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	vulnMutex.Lock()
	pkgMap[pkgInfo.AgentId] = append(pkgMap[pkgInfo.AgentId], pkgInfo)
	if len(pkgMap[pkgInfo.AgentId]) >= 100 {
		dbtask.LeaderVulnAsyncWrite(pkgMap[pkgInfo.AgentId])
		delete(pkgMap, pkgInfo.AgentId)
	}
	vulnMutex.Unlock()
	common.CreateResponse(c, common.SuccessCode, "ok")
	return
}

// 定时清空agent软件包信息
const FlushVulnPkgInfoLock = "FlushVulnPkgInfoLock"

func FlushPkgInfo() {
	myFunc := func() {
		timer := time.NewTicker(time.Second * time.Duration(5))
		for {
			select {
			case <-timer.C:
				// 定时清空pkgInfo队列信息
				vulnMutex.Lock()
				for agentId := range pkgMap {
					if len(pkgMap[agentId]) > 0 {
						dbtask.LeaderVulnAsyncWrite(pkgMap[agentId])
						delete(pkgMap, agentId)
					}
				}
				vulnMutex.Unlock()
			}
		}
	}

	lockSuccess, err := infra.Grds.SetNX(context.Background(), FlushVulnPkgInfoLock, 1, time.Minute*time.Duration(5)).Result()
	if err != nil || !lockSuccess {
		return
	} else {
		myFunc()
		_, err := infra.Grds.Del(context.Background(), FlushVulnPkgInfoLock).Result()
		if err != nil {
			return
		}
	}
}

// 清空CPE缓存

// 获取漏洞统计信息
func GetVulnStatistics(c *gin.Context) {
	request := struct {
		AgentId            string `json:"agent_id"`
		IfHighAvailability bool   `json:"if_high_availability"`
	}{}

	type Response struct {
		Processed      int   `json:"processed"`
		UnProcessed    int   `json:"unprocessed"`
		Ignore         int   `json:"ignore"`
		Low            int   `json:"low"`
		Mid            int   `json:"mid"`
		High           int   `json:"high"`
		Danger         int   `json:"danger"`
		VulnLibVersion int64 `json:"vuln_lib_version"`
		IfAutoUpdate   bool  `json:"if_auto_update"`
		IfLargeAgent   bool  `json:"if_large_agent"`
	}
	var response Response

	type VulnInfo struct {
		Level  string `json:"level" bson:"level"`
		Status string `json:"status" bson:"status"`
	}

	// 绑定请求信息
	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)
	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)
	CronJobCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CronjobCollection)

	// 生成当前版本信息
	var vulnConf vuln.VulnConfUpdate
	err = vulnConfCol.FindOne(c, bson.M{"type": vuln.VulnConfAutoUpdate}).Decode(&vulnConf)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	response.VulnLibVersion = vulnConf.VulnLibVersion
	response.IfAutoUpdate = vulnConf.IfAutoUpdate

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if request.IfHighAvailability {
		searchFilter["action"] = vuln.VulnActionBlock
	}
	if request.AgentId != "" {
		var vulnIdList []int64
		searchAgentFilter := make(map[string]interface{})
		searchAgentFilter["agent_id"] = request.AgentId
		searchAgentFilter["drop_status"] = vuln.VulnDropStatusUse
		if request.IfHighAvailability {
			searchAgentFilter["action"] = vuln.VulnActionBlock
		}
		cursor, _ := agentVulnCol.Find(c, searchAgentFilter, options.Find().SetProjection(bson.M{"vuln_id": 1, "status": 1, "level": 1}))
		for cursor.Next(c) {
			tmpStruct := struct {
				VulnId int64  `bson:"vuln_id"`
				Status string `bson:"status"`
				Level  string `bson:"level"`
			}{}
			err := cursor.Decode(&tmpStruct)
			if err != nil {
				continue
			}
			vulnIdList = append(vulnIdList, tmpStruct.VulnId)
			switch tmpStruct.Status {
			case vuln.VulnStatusUnProcessed:
				response.UnProcessed++
				switch tmpStruct.Level {
				case vuln.LowLevel:
					response.Low++
				case vuln.MidLevel:
					response.Mid++
				case vuln.HighLevel:
					response.High++
				case vuln.DangerLevel:
					response.Danger++
				}
			case vuln.VulnStatusProcessed:
				response.Processed++
			case vuln.VulnStatusIgnored:
				response.Ignore++
			}
		}
	} else {
		cursor, err := vulnHeartCol.Find(c, searchFilter)
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err)
			return
		}

		defer func() {
			_ = cursor.Close(c)
		}()

		// 迭代返回数据
		for cursor.Next(c) {
			var vulnHeart vuln.VulnHeart
			err := cursor.Decode(&vulnHeart)
			if err != nil {
				continue
			}

			// 计算漏洞风险数量
			if vulnHeart.InfectStatus.UnProcessed > 0 {
				switch vulnHeart.Level {
				case vuln.LowLevel:
					response.Low++
				case vuln.MidLevel:
					response.Mid++
				case vuln.HighLevel:
					response.High++
				case vuln.DangerLevel:
					response.Danger++
				}
				response.UnProcessed++
			}
			if vulnHeart.InfectStatus.Processed > 0 {
				response.Processed++
			}
			if vulnHeart.InfectStatus.Ignore > 0 {
				response.Ignore++
			}
		}
	}

	// 拼接资产数量是否过多信息
	tmpStruct := struct {
		Running int `bson:"running"`
	}{}
	err = CronJobCol.FindOne(c, bson.M{"api": "/api/v6/asset-center/DescribeHostStatistics"}).Decode(&tmpStruct)
	if err != nil {
		return
	}
	if tmpStruct.Running >= vuln.LargeAgent {
		response.IfLargeAgent = true
	} else {
		response.IfLargeAgent = false
	}

	common.CreateResponse(c, common.SuccessCode, response)
	return
}

// 获取漏洞列表
func GetVulnList(c *gin.Context) {
	go vuln.JudgeVulnTaskTimeout()
	type VulnRequest struct {
		VulnName           string   `json:"vuln_name,omitempty" bson:"vuln_name,omitempty"`
		CveId              string   `json:"cve_id,omitempty" bson:"cve_id,omitempty"`
		Level              []string `json:"level,omitempty" bson:"level,omitempty"`
		Status             []string `json:"status,omitempty" bson:"status,omitempty"`
		Tag                []string `json:"tag,omitempty" bson:"tag,omitempty"`
		AgentId            string   `json:"agent_id,omitempty" bson:"agent_id,omitempty"`
		IfHighAvailability bool     `json:"if_high_availability" bson:"if_high_availability"`
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定漏洞筛选数据
	var vulnRequest VulnRequest
	err = c.BindJSON(&vulnRequest)
	if err != nil {
		ylog.Errorf("GetVulnList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}
	if len(vulnRequest.Status) < 1 {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "status number < 1")
		return
	}
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)

	// 拼接mongo查询语句
	agentVulnInfoFilter := make(map[string]interface{})
	if vulnRequest.AgentId != "" {
		vulnIdList := make([]int64, 0, 0)
		cursor, _ := agentVulnCol.Find(c, bson.M{"agent_id": vulnRequest.AgentId, "status": vulnRequest.Status[0]}, options.Find().SetProjection(bson.M{"vuln_id": 1}))
		for cursor.Next(c) {
			tmpStruct := struct {
				VulnId int64 `bson:"vuln_id"`
			}{}
			err := cursor.Decode(&tmpStruct)
			if err != nil {
				continue
			}
			vulnIdList = append(vulnIdList, tmpStruct.VulnId)
		}
		agentVulnInfoFilter["vuln_id"] = common.MongoInside{Inside: vulnIdList}
	}
	if vulnRequest.CveId != "" {
		agentVulnInfoFilter["cve_id"] = common.MongoRegex{Regex: vulnRequest.CveId}
	}
	if len(vulnRequest.Level) != 0 {
		agentVulnInfoFilter["level"] = common.MongoInside{Inside: vulnRequest.Level}
	}
	if len(vulnRequest.Status) != 0 {
		for _, status := range vulnRequest.Status {
			switch status {
			case vuln.VulnStatusUnProcessed:
				agentVulnInfoFilter["infect_status.unprocessed"] = common.MongoNe{Value: 0}
			case vuln.VulnStatusProcessed:
				agentVulnInfoFilter["infect_status.processed"] = common.MongoNe{Value: 0}
			case vuln.VulnStatusIgnored:
				agentVulnInfoFilter["infect_status.ignore"] = common.MongoNe{Value: 0}
			}
		}
	}
	if vulnRequest.VulnName != "" {
		agentVulnInfoFilter["vuln_name"] = common.MongoRegex{Regex: vulnRequest.VulnName}
	}
	if vulnRequest.IfHighAvailability {
		agentVulnInfoFilter["action"] = vuln.VulnActionBlock
	}
	if len(vulnRequest.Tag) != 0 {
		if len(vulnRequest.Tag) == 1 {
			agentVulnInfoFilter["tag"] = common.MongoInside{Inside: vulnRequest.Tag}
		} else {
			var andFilter bson.A
			for _, tag := range vulnRequest.Tag {
				andFilter = append(andFilter, bson.M{"tag": tag})
				agentVulnInfoFilter["$and"] = andFilter
			}
		}
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: agentVulnInfoFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// 聚合查询
	var dataResponse []vuln.VulnHeart

	pageResponse, err := common.DBSearchPaginate(
		vulnHeartCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var vulnHeart vuln.VulnHeart
			err := cursor.Decode(&vulnHeart)
			if err != nil {
				ylog.Errorf("vulnHeart", err.Error())
				return err
			}
			switch vulnRequest.Status[0] {
			case vuln.VulnStatusUnProcessed:
				vulnHeart.InfectNum = vulnHeart.InfectStatus.UnProcessed
				vulnHeart.OperateReason = ""
			case vuln.VulnStatusProcessed:
				vulnHeart.InfectNum = vulnHeart.InfectStatus.Processed
				vulnHeart.UpdateTime = vulnHeart.ControlTime
			case vuln.VulnStatusIgnored:
				vulnHeart.InfectNum = vulnHeart.InfectStatus.Ignore
				vulnHeart.UpdateTime = vulnHeart.ControlTime
			}

			dataResponse = append(dataResponse, vulnHeart)
			return nil
		},
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 查看一个漏洞信息
func GetVulnInfo(c *gin.Context) {
	var vulnInfo vuln.VulnInfo

	// 绑定漏洞信息
	request := struct {
		VulnId  int    `json:"vuln_id" bson:"vuln_id"`
		AgentId string `json:"agent_id" bson:"agent_id"`
	}{}

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetVulnInfo", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, vulnInfo)
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	err = collection.FindOne(c, bson.M{"id": request.VulnId}).Decode(&vulnInfo)
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 获取漏洞对应软件信息
	if request.AgentId != "" {
		var vulnSoftInfo vuln.AgentVulnSoftInfo
		collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnSoftInfo)
		err = collection.FindOne(c, bson.M{"vuln_id": request.VulnId, "agent_id": request.AgentId}).Decode(&vulnSoftInfo)
		if err != nil && err != mongo.ErrNoDocuments {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		vulnInfo.CpeName = vulnSoftInfo.PackageName
		vulnInfo.CpeVersion = vulnSoftInfo.PackageVersion
	}

	// 枚举level信息
	levelMap := map[string]string{
		"1": "low",
		"2": "low",
		"3": "mid",
		"4": "high",
		"5": "danger",
	}
	vulnInfo.Level = levelMap[vulnInfo.Level]

	// 如果中文信息不完善，展示英文
	if len(vulnInfo.VulnName) == 0 || c.Request.Header.Get(HeaderLang) == LangEN {
		vulnInfo.Descript = vulnInfo.DescriptEn
	}

	common.CreateResponse(c, common.SuccessCode, vulnInfo)
}

// 获取漏洞影响资产列表
func VulnHostList(c *gin.Context) {

	// 返回的主机数据
	type responseStruct struct {
		HostName      string `json:"host_name" bson:"hostname"`
		IntranetIp    string `json:"intranet_ip" bson:"intranet_ip"`
		ExtranetIp    string `json:"extranet_ip" bson:"extranet_ip"`
		UpdateTime    int64  `json:"update_time" bson:"update_time"`
		CreateTime    int64  `json:"create_time" bson:"create_time"`
		ControlTime   int64  `json:"control_time" bson:"control_time"`
		Status        string `json:"status" bson:"status"`
		AgentId       string `json:"agent_id" bson:"agent_id"`
		OperateReason string `json:"operate_reason" bson:"operate_reason"`
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定漏洞筛选数据
	request := struct {
		Status   []string `json:"status" bson:"status"`
		VulnId   int64    `json:"vuln_id" bson:"vuln_id"`
		HostName string   `json:"host_name" bson:"host_name"`
		Ip       string   `json:"ip" bson:"ip"`
	}{}
	err = c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if request.VulnId != 0 {
		searchFilter["vuln_id"] = request.VulnId
	}
	if len(request.Status) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: request.Status}
	}
	searchFilter["drop_status"] = vuln.VulnDropStatusUse

	// 主机过滤条件
	searchHostFilter := make(map[string]interface{})
	if request.HostName != "" {
		searchHostFilter["agent_info.hostname"] = common.MongoRegex{Regex: request.HostName}
	}
	if request.Ip != "" {
		searchHostFilter["$or"] = []bson.M{
			{"agent_info.intranet_ipv4": request.Ip}, {"agent_info.extranet_ipv4": request.Ip},
		}
	}

	var aggregateSearchList bson.A
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchFilter})

	// 连表查询
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from":         infra.AgentHeartBeatCollection,
		"localField":   "agent_id",
		"foreignField": "agent_id",
		"as":           "agent_info",
	}})

	if len(searchHostFilter) != 0 {
		aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchHostFilter})
	}

	aggregateSearchList = append(aggregateSearchList, bson.M{"$project": bson.M{
		"agent_id":       1,
		"status":         1,
		"create_time":    1,
		"update_time":    1,
		"operate_reason": 1,
		"intranet_ipv4":  "$agent_info.intranet_ipv4",
		"extranet_ipv4":  "$agent_info.extranet_ipv4",
		"hostname":       "$agent_info.hostname",
	}})

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// 获取漏洞信息
	type MongoStruct struct {
		UpdateTime    int64      `json:"update_time" bson:"update_time"`
		CreateTime    int64      `json:"create_time" bson:"create_time"`
		Status        string     `json:"status" bson:"status"`
		AgentId       string     `json:"agent_id" bson:"agent_id"`
		HostName      []string   `json:"host_name" bson:"hostname"`
		ExtranetIpv4  [][]string `json:"extranet_ipv_4" bson:"extranet_ipv4"`
		IntranetIpv4  [][]string `json:"intranet_ipv4" bson:"intranet_ipv4"`
		OperateReason string     `json:"operate_reason" bson:"operate_reason"`
	}
	var dataResponse []responseStruct
	pageResponse, err := common.DBAggregatePaginate(
		collection,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var response responseStruct
			var mongoStruct MongoStruct

			err := cursor.Decode(&mongoStruct)
			response.UpdateTime = mongoStruct.UpdateTime
			response.CreateTime = mongoStruct.CreateTime
			response.Status = mongoStruct.Status
			response.AgentId = mongoStruct.AgentId
			response.OperateReason = mongoStruct.OperateReason
			if len(mongoStruct.HostName) > 0 {
				response.HostName = mongoStruct.HostName[0]
			}
			if len(mongoStruct.ExtranetIpv4) > 0 && len(mongoStruct.ExtranetIpv4[0]) > 0 {
				response.ExtranetIp = mongoStruct.ExtranetIpv4[0][0]
			}
			if len(mongoStruct.IntranetIpv4) > 0 && len(mongoStruct.IntranetIpv4[0]) > 0 {
				response.IntranetIp = mongoStruct.IntranetIpv4[0][0]
			}

			if err != nil {
				return err
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

// 处理主机漏洞
func VulnIpControl(c *gin.Context) {

	// 绑定筛选条件
	request := struct {
		VulnId       int64    `json:"vuln_id,omitempty" bson:"vuln_id"`
		AgentIdList  []string `json:"agent_id_list,omitempty" bson:"agent_id_list"`
		IfAll        bool     `json:"if_all,omitempty" bson:"if_all"`
		BeforeStatus string   `json:"before_status,omitempty" bson:"before_status"`
		AfterStatus  string   `json:"after_status,omitempty" bson:"after_status"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	searchFilter := make(map[string]interface{})
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)

	// 更新一个主机的所有漏洞
	if request.VulnId == 0 {
		if request.IfAll {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "can only choose one agent")
		}
		if len(request.AgentIdList) != 1 {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "can only choose one agent")
		}
		agentId := request.AgentIdList[0]
		searchFilter["agent_id"] = agentId
		_, err := collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "control_time": time.Now().Unix()}})
		if err != nil && err != mongo.ErrNoDocuments {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

	} else {

		// 更新单个漏洞的部分主机
		searchFilter["status"] = request.BeforeStatus
		if request.VulnId != 0 {
			searchFilter["vuln_id"] = request.VulnId
		}

		// 获取agent列表
		var agentList []string

		if !request.IfAll {
			if len(request.AgentIdList) != 0 {
				agentList = request.AgentIdList
			} else {
				common.CreateResponse(c, common.ParamInvalidErrorCode, "can not find agent_id")
				return
			}
		} else {
			cur, err := collection.Find(c, searchFilter, options.Find().SetProjection(bson.M{"agent_id": 1}))
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
				agentList = append(agentList, idStruct.AgentId)
			}
		}
		if len(agentList) == 0 {
			common.CreateResponse(c, common.ParamInvalidErrorCode, "not match agent_id")
			return
		} else {
			searchFilter["agent_id"] = common.MongoInside{Inside: agentList}
		}

		// 更新漏洞
		_, err = collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "control_time": time.Now().Unix()}})
		if err != nil && err != mongo.ErrNoDocuments {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

	}

	go vuln.CalcuVulnList("once")
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// 处理单个主机漏洞
func OneIpVulnControl(c *gin.Context) {

	// 绑定筛选条件
	request := struct {
		AgentId      string  `json:"agent_id" bson:"agent_id"`
		VulnIdList   []int64 `json:"vuln_id_list,omitempty" bson:"vuln_id_list"`
		IfAll        bool    `json:"if_all,omitempty" bson:"if_all"`
		BeforeStatus string  `json:"before_status,omitempty" bson:"before_status"`
		AfterStatus  string  `json:"after_status,omitempty" bson:"after_status"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)

	// 获取该IP当前未处理个数
	searchFilter := make(map[string]interface{})
	searchFilter["agent_id"] = request.AgentId
	searchFilter["status"] = vuln.VulnStatusUnProcessed

	// 拼接mongo查询语句
	searchFilter = make(map[string]interface{})
	if !request.IfAll {
		if len(request.VulnIdList) != 0 {
			searchFilter["vuln_id"] = common.MongoInside{Inside: request.VulnIdList}
		}
	}
	searchFilter["agent_id"] = request.AgentId
	searchFilter["status"] = request.BeforeStatus

	_, err = collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "control_time": time.Now().Unix()}})
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	go vuln.CalcuVulnList("once")
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// 批量处理漏洞
func VulnControl(c *gin.Context) {

	// 绑定筛选条件
	request := struct {
		VulnIdList   []int64 `json:"vuln_id_list,omitempty" bson:"vuln_id_list"`
		IfAll        bool    `json:"if_all,omitempty" bson:"if_all"`
		BeforeStatus string  `json:"before_status,omitempty" bson:"before_status"`
		AfterStatus  string  `json:"after_status,omitempty" bson:"after_status"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if !request.IfAll {
		if len(request.VulnIdList) != 0 {
			searchFilter["vuln_id"] = common.MongoInside{Inside: request.VulnIdList}
		}
	}
	searchFilter["status"] = request.BeforeStatus

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	_, err = collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus}})
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	go vuln.CalcuVulnList("once")
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// 处理漏洞(新)
func VulnControlNew(c *gin.Context) {
	request := struct {
		VulnIdList   []int64  `json:"vuln_id_list" bson:"vuln_id_list"`
		AgentIdList  []string `json:"agent_id_list" bson:"agent_id_list"`
		BeforeStatus string   `json:"before_status" bson:"before_status"`
		AfterStatus  string   `json:"after_status" bson:"after_status"`
		Reason       string   `json:"reason" bson:"reason"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)

	// 计算并更新漏洞状态
	if len(request.VulnIdList) == 1 {
		var changeNum int
		if len(request.AgentIdList) == 0 {
			var vulnHeart vuln.VulnHeart
			err := vulnHeartCol.FindOne(c, bson.M{"vuln_id": request.VulnIdList[0]}).Decode(&vulnHeart)
			if err != nil {
				ylog.Infof("Find error", err.Error())
			}
			switch request.BeforeStatus {
			case vuln.VulnStatusUnProcessed:
				changeNum = vulnHeart.InfectStatus.UnProcessed
			case vuln.VulnStatusProcessed:
				changeNum = vulnHeart.InfectStatus.Processed
			case vuln.VulnStatusIgnored:
				changeNum = vulnHeart.InfectStatus.Ignore
			}
		}
		if len(request.AgentIdList) != 0 {
			changeNum = len(request.AgentIdList)
		}

		updateBson := bson.M{}
		switch request.BeforeStatus {
		case vuln.VulnStatusUnProcessed:
			updateBson["infect_status.unprocessed"] = 0 - changeNum
		case vuln.VulnStatusProcessed:
			updateBson["infect_status.processed"] = 0 - changeNum
		case vuln.VulnStatusIgnored:
			updateBson["infect_status.ignore"] = 0 - changeNum
		}
		switch request.AfterStatus {
		case vuln.VulnStatusUnProcessed:
			updateBson["infect_status.unprocessed"] = changeNum
		case vuln.VulnStatusProcessed:
			updateBson["infect_status.processed"] = changeNum
		case vuln.VulnStatusIgnored:
			updateBson["infect_status.ignore"] = changeNum
		}
		_, err := vulnHeartCol.UpdateOne(c, bson.M{"vuln_id": request.VulnIdList[0]}, bson.M{"$inc": updateBson})
		if err != nil {
			ylog.Errorf("Update error", err.Error())
		}
	}
	if len(request.AgentIdList) == 1 {
		updateBson := bson.M{}
		if len(request.VulnIdList) == 0 {
			cur, _ := agentVulnCol.Find(c, bson.M{"agent_id": request.AgentIdList[0]})
			for cur.Next(c) {
				var agentVulnInfo vuln.AgentVulnInfo
				err := cur.Decode(&agentVulnInfo)
				if err != nil {
					continue
				}
				request.VulnIdList = append(request.VulnIdList, agentVulnInfo.VulnId)
			}
		}
		switch request.BeforeStatus {
		case vuln.VulnStatusUnProcessed:
			updateBson["infect_status.unprocessed"] = -1
		case vuln.VulnStatusProcessed:
			updateBson["infect_status.processed"] = -1
		case vuln.VulnStatusIgnored:
			updateBson["infect_status.ignore"] = -1
		}
		switch request.AfterStatus {
		case vuln.VulnStatusUnProcessed:
			updateBson["infect_status.unprocessed"] = 1
		case vuln.VulnStatusProcessed:
			updateBson["infect_status.processed"] = 1
		case vuln.VulnStatusIgnored:
			updateBson["infect_status.ignore"] = 1
		}
		_, err := vulnHeartCol.UpdateMany(c, bson.M{"vuln_id": bson.M{"$in": request.VulnIdList[0]}}, bson.M{"$inc": updateBson})
		if err != nil {
			ylog.Errorf("Update error", err.Error())
		}
	}

	// 更新agent_vuln_info
	searchFilter := make(map[string]interface{})
	if len(request.VulnIdList) != 0 {
		if len(request.VulnIdList) != 0 {
			searchFilter["vuln_id"] = common.MongoInside{Inside: request.VulnIdList}
		}
	}
	if len(request.AgentIdList) != 0 {
		if len(request.AgentIdList) != 0 {
			searchFilter["agent_id"] = common.MongoInside{Inside: request.AgentIdList}
		}
	}
	searchFilter["status"] = request.BeforeStatus
	_, err = agentVulnCol.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "operate_reason": request.Reason}})
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 如果是处理整个漏洞，更新漏洞心跳表处理原因
	if len(request.AgentIdList) == 0 && len(request.VulnIdList) != 0 {
		vulnHeartFilter := make(map[string]interface{})
		vulnHeartFilter["vuln_id"] = common.MongoInside{Inside: request.VulnIdList}
		if request.BeforeStatus == vuln.VulnStatusUnProcessed {
			_, err = vulnHeartCol.UpdateMany(c, vulnHeartFilter, bson.M{"$set": bson.M{"control_time": time.Now().Unix(), "operate_reason": request.Reason, "status": request.AfterStatus}})
		} else if request.AfterStatus == vuln.VulnStatusUnProcessed {
			_, err = vulnHeartCol.UpdateMany(c, vulnHeartFilter, bson.M{"$set": bson.M{"control_time": time.Now().Unix(), "operate_reason": "", "status": request.AfterStatus}})
		}
		if err != nil && err != mongo.ErrNoDocuments {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	time.Sleep(time.Duration(1) * time.Second)
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// 导出漏洞影响资产数据
func DownloadVulnData(c *gin.Context) {
	// 绑定筛选条件
	request := struct {
		VulnId    int64    `json:"vuln_id" bson:"vuln_id"`
		Status    []string `json:"status,omitempty" bson:"status,omitempty"`
		AgentList []string `json:"agent_list,omitempty" bson:"agent_list,omitempty"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if len(request.Status) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: request.Status}
	}
	if len(request.AgentList) != 0 {
		searchFilter["agent_id"] = common.MongoInside{Inside: request.AgentList}
	}
	searchFilter["vuln_id"] = request.VulnId
	searchFilter["drop_status"] = vuln.VulnDropStatusUse

	aggregateSearchList := make(bson.A, 0)
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchFilter})
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from":         infra.AgentHeartBeatCollection,
		"localField":   "agent_id",
		"foreignField": "agent_id",
		"as":           "agent_info",
	}})
	aggregateSearchList = append(aggregateSearchList, bson.M{"$project": bson.M{
		"agent_id":      1,
		"status":        1,
		"create_time":   1,
		"update_time":   1,
		"intranet_ipv4": "$agent_info.intranet_ipv4",
		"extranet_ipv4": "$agent_info.extranet_ipv4",
		"hostname":      "$agent_info.hostname",
	}})
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)

	var exportList [][]string
	type ExportStruct struct {
		AgentId      string     `bson:"agent_id"`
		Hostname     []string   `bson:"hostname"`
		IntranetIpv4 [][]string `bson:"intranet_ipv4"`
		ExtranetIpv4 [][]string `bson:"extranet_ipv4"`
		Status       string     `bson:"status"`
		CreateTime   int64      `bson:"create_time"`
		UpdateTime   int64      `bson:"update_time"`
	}
	var exportStruct ExportStruct
	cursor, _ := agentVulnCol.Aggregate(c, aggregateSearchList)
	for cursor.Next(c) {
		err = cursor.Decode(&exportStruct)
		exportData := make([]string, 0, 7)
		exportData = append(exportData, exportStruct.AgentId)
		if len(exportStruct.Hostname) >= 1 {
			exportData = append(exportData, exportStruct.Hostname[0])
		} else {
			exportData = append(exportData, "")
		}
		if len(exportStruct.IntranetIpv4) >= 1 && len(exportStruct.IntranetIpv4[0]) >= 1 {
			exportData = append(exportData, exportStruct.IntranetIpv4[0][0])
		} else {
			exportData = append(exportData, "")
		}
		if len(exportStruct.ExtranetIpv4) >= 1 && len(exportStruct.ExtranetIpv4[0]) >= 1 {
			exportData = append(exportData, exportStruct.ExtranetIpv4[0][0])
		} else {
			exportData = append(exportData, "")
		}
		exportData = append(exportData, exportStruct.Status)
		createTimeobj := time.Unix(exportStruct.CreateTime, 0)
		exportData = append(exportData, createTimeobj.Format("2006-01-02 15:04:05"))
		updateTimeobj := time.Unix(exportStruct.UpdateTime, 0)
		exportData = append(exportData, updateTimeobj.Format("2006-01-02 15:04:05"))
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "agent_id", Header: "agent_id"},
		{Key: "hostname", Header: "hostname"},
		{Key: "intranet_ipv4", Header: "intranet_ipv4"},
		{Key: "extranet_ipv4", Header: "extranet_ipv4"},
		{Key: "status", Header: "status"},
		{Key: "create_time", Header: "create_time"},
		{Key: "update_time", Header: "update_time"},
	}

	vulnInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	var vulnInfo vuln.VulnInfo
	err = vulnInfoCol.FindOne(c, bson.M{"id": request.VulnId}).Decode(&vulnInfo)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}

	filename := vulnInfo.CveId + "infected-assets" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 导出漏洞数据
func DownloadVulnList(c *gin.Context) {
	// 绑定筛选条件
	request := struct {
		IdList     []int `json:"id_list" bson:"id_list"`
		Conditions struct {
			VulnName string   `json:"vuln_name" bson:"vuln_name"`
			CveId    string   `json:"cve_id" bson:"cve_id"`
			Level    []string `json:"level" bson:"level"`
			Tag      []string `json:"tag" bson:"tag"`
			Status   []string `json:"status" bson:"status"`
			AgentId  string   `json:"agent_id" bson:"agent_id"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 获取漏洞-agent_id关联字典
	vulnAgentMap := make(map[int64][]string)
	vulnList := make([]int64, 0)
	searchFilter := make(map[string]interface{})
	searchFilter["drop_status"] = vuln.VulnDropStatusUse

	if len(request.IdList) != 0 {
		searchFilter["vuln_id"] = common.MongoInside{Inside: request.IdList}
	}
	if request.Conditions.AgentId != "" {
		searchFilter["agent_id"] = request.Conditions.AgentId
	}
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)

	aggregateSearchList := make(bson.A, 0)
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": searchFilter})
	aggregateSearchList = append(aggregateSearchList, bson.M{"$group": bson.M{
		"_id":           "$vuln_id",
		"agent_id_list": bson.M{"$addToSet": "$agent_id"},
	}})

	cursor, err := agentVulnCol.Aggregate(c, aggregateSearchList)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	for cursor.Next(c) {
		tmpStruct := struct {
			AgentIdList []string `bson:"agent_id_list"`
			VulnId      int64    `bson:"_id"`
		}{}
		_ = cursor.Decode(&tmpStruct)
		vulnAgentMap[tmpStruct.VulnId] = tmpStruct.AgentIdList
		vulnList = append(vulnList, tmpStruct.VulnId)
	}

	// 拼接mongo查询语句
	searchFilter = make(map[string]interface{})
	if len(vulnList) == 0 {
		common.CreateResponse(c, common.DBOperateErrorCode, "not find")
		return
	} else {
		searchFilter["vuln_id"] = common.MongoInside{Inside: vulnList}
	}
	if len(request.Conditions.Status) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: request.Conditions.Status}
	}
	if len(request.Conditions.Level) != 0 {
		searchFilter["level"] = common.MongoInside{Inside: request.Conditions.Level}
	}
	if len(request.Conditions.Tag) != 0 {
		searchFilter["tag"] = common.MongoInside{Inside: request.Conditions.Tag}
	}
	if request.Conditions.VulnName != "" {
		searchFilter["vuln_name"] = common.MongoRegex{Regex: request.Conditions.VulnName}
	}
	if request.Conditions.CveId != "" {
		searchFilter["cve_id"] = common.MongoRegex{Regex: request.Conditions.CveId}
	}

	cursor, err = vulnHeartCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	type ExportStruct struct {
		VulnId     int64    `json:"vuln_id" bson:"vuln_id"`
		Level      string   `json:"level" bson:"level"`
		CveId      string   `json:"cve_id" bson:"cve_id"`
		VulnName   string   `json:"vuln_name" bson:"vuln_name"`
		VulnNameEn string   `json:"vuln_name_en" bson:"vuln_name_en"`
		Tag        []string `json:"tag" bson:"tag"`
		Status     string   `json:"status" bson:"status"`
	}
	var exportStruct ExportStruct
	var exportList [][]string
	for cursor.Next(c) {
		err := cursor.Decode(&exportStruct)
		if err != nil {
			continue
		}
		exportData := make([]string, 0, 8)

		exportData = append(exportData, strconv.FormatInt(exportStruct.VulnId, 10))
		exportData = append(exportData, exportStruct.Level)
		exportData = append(exportData, exportStruct.CveId)
		exportData = append(exportData, exportStruct.VulnName)
		exportData = append(exportData, exportStruct.VulnNameEn)
		exportData = append(exportData, exportStruct.Status)
		exportData = append(exportData, strings.Join(exportStruct.Tag, ","))
		exportData = append(exportData, strings.Join(vulnAgentMap[exportStruct.VulnId], ","))
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "vuln_id", Header: "vuln_id"},
		{Key: "level", Header: "level"},
		{Key: "cve_id", Header: "cve_id"},
		{Key: "vuln_name", Header: "vuln_name"},
		{Key: "vuln_name_en", Header: "vuln_name_en"},
		{Key: "tag", Header: "tag"},
		{Key: "status", Header: "status"},
		{Key: "agent_list", Header: "agent_list"},
	}

	filename := "vuln_infected-assets" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 开始漏洞检查
func VulnDetect(c *gin.Context) {
	type Request struct {
		HostList  []string `json:"host_list" bson:"host_list"`
		IfAllHost bool     `json:"if_all_host" bson:"if_all_host"`
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
		ylog.Errorf("Detect", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, response)
		return
	}

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

	err = vuln.StartDetect(request.HostList, userName)
	if err != nil {
		ylog.Errorf("Detect", err.Error())
		common.CreateResponse(c, common.UnknownErrorCode, response)
		return
	}

	response.Status = baseline.StatusSuccess
	common.CreateResponse(c, common.SuccessCode, response)
	return
}

// 查看漏洞整体检测状态
func VulnCheckStatus(c *gin.Context) {

	type Response struct {
		Status        string `json:"status"`
		Progress      int64  `json:"progress"`
		LastCheckTime int64  `json:"last_check_time"`
	}
	var response Response

	// 绑定筛选数据
	vulnStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnStatus)
	vulnTaskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnTaskStatus)

	var vulnStatus vuln.VulnStatus
	err := vulnStatusCol.FindOne(c, bson.M{"id": 0}).Decode(&vulnStatus)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}

	// 获取最近检查时间
	todayUnix := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 1, 30, 0, 0, time.Now().Location()).Unix()

	if vulnStatus.LastCheckTime > todayUnix || vulnStatus.LastCheckTime == 0 {
		response.LastCheckTime = vulnStatus.LastCheckTime
	} else {
		response.LastCheckTime = todayUnix
	}

	// 判断策略组运行状态
	if vulnStatus.Status == "finished" {
		response.Status = "finished"
		response.Progress = 100
		_, err := vulnStatusCol.UpdateOne(c, bson.M{"id": 0},
			bson.M{"$set": bson.M{"last_check_time": response.LastCheckTime, "status": "finished"}})
		if err != nil {
			ylog.Errorf("UpdateOne error", err.Error())
		}
	} else {
		searchFilter := make(map[string]interface{})
		searchFilter["status"] = "running"
		res := vulnTaskStatusCol.FindOne(c, searchFilter)
		if res.Err() == nil {
			response.Status = "running"
			runTotal, _ := vulnTaskStatusCol.CountDocuments(c, searchFilter)
			searchFilter["status"] = "finished"
			total, _ := vulnTaskStatusCol.CountDocuments(c, bson.M{})
			finishedTotal := total - runTotal
			response.Progress = finishedTotal * 100 / total
		} else {
			response.Status = "finished"
			response.Progress = 100
			_, err := vulnStatusCol.UpdateOne(c, bson.M{"id": 0},
				bson.M{"$set": bson.M{"last_check_time": response.LastCheckTime, "status": "finished"}})
			if err != nil {
				ylog.Errorf("Update error", err.Error())
			}
		}
	}

	common.CreateResponse(c, common.SuccessCode, response)
}

// 漏洞检查进度详情
func VulnDetectProgressDetail(c *gin.Context) {
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
			DangerNum int `json:"danger_num"`
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

	vulnStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnStatus)
	vulnTaskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnTaskStatus)
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)

	// 获取检查状态
	searchFilter := make(map[string]interface{})
	searchFilter["status"] = "running"
	res := vulnStatusCol.FindOne(c, searchFilter)
	if res.Err() == nil {
		response.Status = "running"
	} else {
		response.Status = "finished"
	}

	// 进度信息，主机数量统计: ProgresDetail，HostNum
	if response.Status == "running" {
		searchFilter = make(map[string]interface{})
		total, _ := vulnTaskStatusCol.CountDocuments(c, searchFilter)
		searchFilter["status"] = "running"
		runTotal, _ := vulnTaskStatusCol.CountDocuments(c, searchFilter)
		finishedTotal := total - runTotal
		response.ProgresDetail.Progress = finishedTotal * 100 / total
		response.ProgresDetail.TimeLeft = runTotal/100 + 1
		response.HostNum.Total = total
		response.HostNum.Finished = finishedTotal
	}

	// 风险数量: RiskNum
	if response.Status == "finished" {
		groupFilter := bson.M{"$group": bson.M{
			"_id":   "$level",
			"count": bson.M{"$sum": 1},
		}}
		aggregateSearchList := make(bson.A, 0)
		aggregateSearchList = append(aggregateSearchList, groupFilter)
		cur, err := agentVulnCol.Aggregate(c, aggregateSearchList)
		resStuct := struct {
			Id    string `bson:"_id"`
			Count int    `bson:"count"`
		}{}
		if err == nil {
			for cur.Next(c) {
				err = cur.Decode(&resStuct)
				if resStuct.Id == "high" {
					response.RiskNum.HighNum = resStuct.Count // 默认所有基线漏洞都是高危，所以先使用简单的查询
				} else if resStuct.Id == "mid" {
					response.RiskNum.MediumNum = resStuct.Count
				} else if resStuct.Id == "low" {
					response.RiskNum.LowNum = resStuct.Count
				} else if resStuct.Id == "danger" {
					response.RiskNum.DangerNum = resStuct.Count
				}
			}
		}
	}

	// 主机详情 HostDetail
	searchFilter = make(map[string]interface{})
	if response.Status == "running" {
		searchFilter["status"] = "running"
	}
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
		"status":   1,
		"msg":      1,
		"hostname": "$agent_info.hostname",
	}})

	errStruct := struct {
		HostName     string `json:"host_name"`
		FailedReason string `json:"failed_reason"`
	}{}
	type HostResponse struct {
		Status   string   `json:"status" bson:"status"`
		Msg      string   `json:"msg" bson:"msg"`
		HostName []string `json:"host_name" bson:"hostname"`
	}
	hostResponseList := make([]HostResponse, 0)

	cur, _ := vulnTaskStatusCol.Aggregate(c, aggregateSearchList)

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
			response.HostDetail.DetectingHost = append(response.HostDetail.DetectingHost, hostname)
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

// 获取单个主机漏洞详情
func GetHostVulnInfo(c *gin.Context) {
	type Request struct {
		AgentId string `json:"agent_id" bson:"agent_id"`
		VulnId  int    `json:"vuln_id" bson:"vuln_id"`
		Pid     string `json:"pid" bson:"pid"`
	}
	var request Request

	type Response struct {
		Hostname   string                   `json:"hostname" bson:"hostname"`
		Platform   string                   `json:"platform" bson:"platform"`
		ExtranetIP string                   `json:"extranet_ip" bson:"extranet_ipv4"`
		IntranetIP string                   `json:"intranet_ip" bson:"intranet_ipv4"`
		Suggest    string                   `json:"suggest" bson:"suggest"`
		Affect     []vuln.AgentVulnSoftInfo `json:"affect" bson:"affect"`
	}
	var response Response

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("Detect", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, response)
		return
	}

	searchFilter := make(map[string]interface{})
	searchFilter["agent_id"] = request.AgentId
	searchFilter["vuln_id"] = request.VulnId
	if request.Pid != "" {
		searchFilter["pid_list.pid"] = request.Pid
	}

	// 获取主机漏洞信息
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnSoftInfo)
	cur, _ := agentVulnCol.Find(c, searchFilter)
	var agentSoftList []vuln.AgentVulnSoftInfo
	err = cur.All(c, &agentSoftList)
	if err != nil {
		ylog.Infof("Decode error", err.Error())
	}
	response.Affect = agentSoftList

	// 获取主机信息
	var hostInfo asset_center.AgentBasicInfo
	hostCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	err = hostCol.FindOne(c, bson.M{"agent_id": request.AgentId}).Decode(&hostInfo)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	response.Hostname = hostInfo.Hostname
	response.Platform = hostInfo.Platform
	if len(hostInfo.ExtranetIPv4) > 0 {
		response.ExtranetIP = hostInfo.ExtranetIPv4[0]
	}
	if len(hostInfo.IntranetIPv4) > 0 {
		response.IntranetIP = hostInfo.IntranetIPv4[0]
	}

	// 获取漏洞信息
	var vulnInfo vuln.VulnInfo
	vulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	err = vulnCol.FindOne(c, bson.M{"id": request.VulnId}).Decode(&vulnInfo)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	response.Suggest = vulnInfo.Suggest

	common.CreateResponse(c, common.SuccessCode, response)
}

// 变更漏洞自动更新状态
