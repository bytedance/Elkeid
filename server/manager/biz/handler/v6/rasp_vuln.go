package v6

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/internal/rasp"
	"github.com/bytedance/Elkeid/server/manager/internal/vuln"
	"strconv"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// 获取漏洞统计信息
func GetRaspVulnStatistics(c *gin.Context) {
	type Response struct {
		Unsafe int `json:"unsafe"`
		Hotfix int `json:"hotfix"`
		Low    int `json:"low"`
		Mid    int `json:"mid"`
		High   int `json:"high"`
		Danger int `json:"danger"`
	}
	var response Response

	raspVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspVulnProcess)

	// 拼接mongo查询语句
	cursor, err := raspVulnCol.Find(c, bson.M{})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err)
		return
	}

	defer func(cursor *mongo.Cursor, ctx context.Context) {
		err := cursor.Close(ctx)
		if err != nil {
		}
	}(cursor, c)

	// 迭代返回数据
	for cursor.Next(c) {
		var raspProcessVuln rasp.RaspProcessVuln
		err := cursor.Decode(&raspProcessVuln)
		if err != nil {
			continue
		}
		switch raspProcessVuln.Status {
		case rasp.RaspVulnUnSafe:
			response.Unsafe++
		case rasp.RaspVulnHotFix:
			response.Hotfix++
		}

		switch raspProcessVuln.Level {
		case vuln.LowLevel:
			response.Low++
		case vuln.MidLevel:
			response.Mid++
		case vuln.HighLevel:
			response.High++
		case vuln.DangerLevel:
			response.Danger++
		}
	}
	common.CreateResponse(c, common.SuccessCode, response)
}

// 获取漏洞列表
func GetRaspVulnList(c *gin.Context) {
	type VulnRequest struct {
		VulnName string   `json:"vuln_name,omitempty" bson:"vuln_name,omitempty"`
		CveId    string   `json:"cve_id,omitempty" bson:"cve_id,omitempty"`
		Level    []string `json:"level,omitempty" bson:"level,omitempty"`
		Status   []string `json:"status,omitempty" bson:"status,omitempty"`
		Tag      []string `json:"tag,omitempty" bson:"tag,omitempty"`
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetRaspVulnList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定漏洞筛选数据
	var vulnRequest VulnRequest
	err = c.BindJSON(&vulnRequest)
	if err != nil {
		ylog.Errorf("GetRaspVulnList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	type Response struct {
		VulnId     int64    `json:"vuln_id" bson:"vuln_id"`
		Level      string   `json:"level" bson:"level"`
		InfectNum  string   `json:"infect_num" bson:"infect_num"`
		CveId      string   `json:"cve_id" bson:"cve_id"`
		VulnName   string   `json:"vuln_name" bson:"vuln_name"`
		Tag        []string `json:"tag" bson:"tag"`
		Status     string   `json:"status" bson:"status"`
		UpdateTime int64    `json:"update_time" bson:"update_time"`
		CreateTime int64    `json:"create_time" bson:"create_time"`
	}
	raspVulnProcessCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspVulnProcess)

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if vulnRequest.CveId != "" {
		searchFilter["cve_id"] = common.MongoRegex{Regex: vulnRequest.CveId}
	}
	if len(vulnRequest.Level) != 0 {
		searchFilter["level"] = common.MongoInside{Inside: vulnRequest.Level}
	}
	if len(vulnRequest.Status) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: vulnRequest.Status}
	}
	if vulnRequest.VulnName != "" {
		searchFilter["vuln_name"] = common.MongoRegex{Regex: vulnRequest.VulnName}
	}
	if len(vulnRequest.Tag) != 0 {
		if len(vulnRequest.Tag) == 1 {
			searchFilter["tag"] = common.MongoInside{Inside: vulnRequest.Tag}
		} else {
			var andFilter bson.A
			for _, tag := range vulnRequest.Tag {
				andFilter = append(andFilter, bson.M{"tag": tag})
				searchFilter["$and"] = andFilter
			}
		}
	}

	// 拼接分页数据
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	aggregateSearchList := bson.A{
		bson.M{"$match": searchFilter},
		bson.M{"$group": bson.M{
			"_id":         "$vuln_id",
			"process_num": bson.M{"$sum": 1},
			"agent_list":  bson.M{"$addToSet": "$agent_id"},
			"cve_id":      bson.M{"$first": "$cve_id"},
			"level":       bson.M{"$first": "$level"},
			"vuln_name":   bson.M{"$first": "$vuln_name"},
			"tag":         bson.M{"$first": "$tag"},
			"create_time": bson.M{"$min": "$create_time"},
			"update_time": bson.M{"$max": "$update_time"},
		}},
		bson.M{"$project": bson.M{
			"vuln_id":     "$_id",
			"vuln_name":   1,
			"process_num": 1,
			"agent_num":   bson.M{"$size": "$agent_list"},
			"cve_id":      1,
			"level":       1,
			"tag":         1,
			"create_time": 1,
			"update_time": 1,
		}},
	}

	type pageStruct struct {
		VulnId     int64    `json:"vuln_id" bson:"vuln_id"`
		VulnName   string   `json:"vuln_name" bson:"vuln_name"`
		AgentNum   int      `json:"agent_num" bson:"agent_num"`
		ProcessNum int      `json:"process_num" bson:"process_num"`
		CveId      string   `json:"cve_id" bson:"cve_id"`
		Level      string   `json:"level" bson:"level"`
		Tag        []string `json:"tag" bson:"tag"`
		CreateTime int64    `json:"create_time" bson:"create_time"`
		UpdateTime int64    `json:"update_time" bson:"update_time"`
	}

	var dataResponse []Response
	pageResponse, err := common.DBAggregatePaginate(
		raspVulnProcessCol,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var tmpS pageStruct
			err := cursor.Decode(&tmpS)
			if err != nil {
				return err
			}
			response := Response{
				VulnId:     tmpS.VulnId,
				VulnName:   tmpS.VulnName,
				CveId:      tmpS.CveId,
				Level:      tmpS.Level,
				Tag:        tmpS.Tag,
				CreateTime: tmpS.CreateTime,
				UpdateTime: tmpS.UpdateTime,
				InfectNum:  strconv.Itoa(tmpS.AgentNum) + "(" + strconv.Itoa(tmpS.ProcessNum) + ")",
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

// rasp漏洞影响进程列表
func RaspVulnProcessList(c *gin.Context) {

	request := struct {
		Status   []string `json:"status" bson:"status"`
		VulnId   int64    `json:"vuln_id" bson:"vuln_id"`
		HostName string   `json:"host_name" bson:"host_name"`
		Ip       string   `json:"ip" bson:"ip"`
		Cmd      string   `json:"cmd" bson:"cmd"`
	}{}
	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("RaspVulnProcessList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 返回的主机数据
	type Response struct {
		AgentPid   string `json:"agent_pid" bson:"agent_pid"`
		HostName   string `json:"host_name" bson:"hostname"`
		Pid        string `json:"pid" bson:"pid"`
		Cmd        string `json:"cmd" bson:"cmd"`
		IntranetIp string `json:"intranet_ip" bson:"intranet_ip"`
		ExtranetIp string `json:"extranet_ip" bson:"extranet_ip"`
		UpdateTime int64  `json:"update_time" bson:"update_time"`
		CreateTime int64  `json:"create_time" bson:"create_time"`
		Status     string `json:"status" bson:"status"`
		AgentId    string `json:"agent_id" bson:"agent_id"`
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if request.VulnId != 0 {
		searchFilter["vuln_id"] = request.VulnId
	}
	if len(request.Status) != 0 {
		searchFilter["status"] = common.MongoInside{Inside: request.Status}
	}
	if request.Cmd != "" {
		searchFilter["cmd"] = common.MongoRegex{Regex: request.Cmd}
	}

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
		"agent_id":      1,
		"status":        1,
		"pid":           1,
		"cmd":           1,
		"create_time":   1,
		"update_time":   1,
		"intranet_ipv4": "$agent_info.intranet_ipv4",
		"extranet_ipv4": "$agent_info.extranet_ipv4",
		"hostname":      "$agent_info.hostname",
	}})

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspVulnProcess)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// 获取漏洞信息
	type MongoStruct struct {
		UpdateTime   int64      `json:"update_time" bson:"update_time"`
		CreateTime   int64      `json:"create_time" bson:"create_time"`
		Pid          string     `json:"pid" bson:"pid"`
		Cmd          string     `json:"cmd" bson:"cmd"`
		Status       string     `json:"status" bson:"status"`
		AgentId      string     `json:"agent_id" bson:"agent_id"`
		HostName     []string   `json:"host_name" bson:"hostname"`
		ExtranetIpv4 [][]string `json:"extranet_ipv_4" bson:"extranet_ipv4"`
		IntranetIpv4 [][]string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	}
	var dataResponse []Response
	pageResponse, err := common.DBAggregatePaginate(
		collection,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var response Response
			var mongoStruct MongoStruct

			err := cursor.Decode(&mongoStruct)
			response.UpdateTime = mongoStruct.UpdateTime
			response.CreateTime = mongoStruct.CreateTime
			response.Status = mongoStruct.Status
			response.AgentId = mongoStruct.AgentId
			response.Pid = mongoStruct.Pid
			response.Cmd = mongoStruct.Cmd
			response.AgentPid = mongoStruct.AgentId + "_" + mongoStruct.Pid
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
