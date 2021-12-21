package v6

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	dbtask "github.com/bytedance/Elkeid/server/manager/task"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PkgInfo struct {
	Name    string `json:"name" bson:"name"`
	Version string `json:"version" bson:"version"`
	Source  string `json:"source" bson:"source"`
	Status  string `json:"status" bson:"status"`
	Vendor  string `json:"vendor" bson:"vendor"`
}

type AgentPkgList struct {
	AgentId  string    `json:"agent_id" bson:"agent_id"`
	Data     []PkgInfo `json:"data" bson:"data"`
	DataType string    `json:"data_type" bson:"data_type"`
}

type AgentVulnInfo struct {
	AgentId        string   `json:"agent_id" bson:"agent_id"`
	VulnId         int64    `json:"vuln_id" bson:"vuln_id"`
	CveId          string   `json:"cve_id" bson:"cve_id"`
	VulnName       string   `json:"vuln_name" bson:"vuln_name"`
	Tag            []string `json:"tag" bson:"tag"`
	Status         string   `json:"status" bson:"status"`
	Level          string   `json:"level" bson:"level"`
	PackageName    string   `json:"package_name" bson:"package_name"`
	PackageVersion string   `json:"package_version" bson:"package_version"`
	CreateTime     int64    `json:"create_time" bson:"create_time"`
	UpdateTime     int64    `json:"update_time" bson:"update_time"`
	ControlTime    int64    `json:"control_time" bson:"control_time"`
}

type VulnInfo struct {
	VulnName   string `json:"vuln_name" bson:"title_cn"`
	CveId      string `json:"cve_id" bson:"cve"`
	Level      string `json:"level" bson:"severity"`
	CpeName    string `json:"cpe_name" bson:"cpe_product"`
	CpeVersion string `json:"cpe_version" bson:"cpe_version"`
	IfExp      int64  `json:"if_exp" bson:"has_payload"`
	Descript   string `json:"descript" bson:"description_cn"`
	Suggest    string `json:"suggest" bson:"solution_cn"`
	ReferUrls  string `json:"refer_urls" bson:"vuln_references"`
	Cwe        string `json:"cwe" bson:"vuln_type_cn"`
	VulnId     int64  `json:"vuln_id" bson:"id"`
	VulnNameEn string `json:"vuln_name_en" bson:"title_en"`
	DescriptEn string `json:"descript_en" bson:"description_en"`
	SuggestEn  string `json:"suggest_en" bson:"solution_en"`
}

type CpeInfo struct {
	CpeName    string `json:"cpe_name" bson:"cpe_product"`
	CpeVersion string `json:"cpe_version" bson:"cpe_version"`
	Vendor     string `json:"vendor" bson:"cpe_vendor"`
}

const (
	VulnStatusUnProcessed = "unprocessed"
	VulnStatusProcessed   = "processed"
	VulnStatusIgnored     = "ignored"
	LowLevel              = "low"
	MidLevel              = "mid"
	HighLevel             = "high"
	DangerLevel           = "danger"

	HasEXP = "存在EXP"
)

// 获取agent软件包信息(hub调用)
func GetAgentPkgList(c *gin.Context) {
	var newAsset map[string]interface{}
	err := c.BindJSON(&newAsset)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 反序列化data字段
	var pkgList []PkgInfo
	if data, ok := newAsset["data"]; ok {
		if sData, ok := data.(string); ok {
			err := json.Unmarshal([]byte(sData), &pkgList)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
		}
	}

	// 绑定软件包列表
	var agentPkgList AgentPkgList
	agentPkgList.AgentId = newAsset["agent_id"].(string)
	agentPkgList.DataType = newAsset["data_type"].(string)
	agentPkgList.Data = pkgList

	dbtask.LeaderVulnAsyncWrite(agentPkgList)
	common.CreateResponse(c, common.SuccessCode, "ok")
	return
}

// 清空CPE缓存
func FlushCpeCache(c *gin.Context) {
	dbtask.CpeCache.Flush()
}

// 获取漏洞统计信息
func GetVulnStatistics(c *gin.Context) {
	type Statustics struct {
		Processed   int64 `json:"processed" bson:"processed"`
		UnProcessed int64 `json:"unprocessed" bson:"unprocessed"`
		Ignore      int64 `json:"ignore" bson:"ignore"`
		Low         int64 `json:"low" bson:"low"`
		Mid         int64 `json:"mid" bson:"mid"`
		High        int64 `json:"high" bson:"high"`
		Danger      int64 `json:"danger" bson:"danger"`
	}
	type VulnInfo struct {
		Level  string `json:"level" bson:"level"`
		Status string `json:"status" bson:"status"`
	}

	// 绑定请求信息
	request := struct {
		AgentId string `json:"agent_id" bson:"agent_id"`
	}{}
	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if request.AgentId != "" {
		searchFilter["agent_id"] = request.AgentId
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	cursor, err := collection.Find(c, searchFilter)
	defer cursor.Close(c)

	// 迭代返回数据
	var statustics Statustics
	for cursor.Next(c) {
		var vulnInfo VulnInfo
		err := cursor.Decode(&vulnInfo)
		if err != nil {
			continue
		}

		switch vulnInfo.Status {
		case VulnStatusProcessed:
			statustics.Processed++
		case VulnStatusIgnored:
			statustics.Ignore++
		case VulnStatusUnProcessed:
			statustics.UnProcessed++
			switch vulnInfo.Level {
			case LowLevel:
				statustics.Low++
			case MidLevel:
				statustics.Mid++
			case HighLevel:
				statustics.High++
			case DangerLevel:
				statustics.Danger++
			}
		}
	}

	common.CreateResponse(c, common.SuccessCode, statustics)
}

// 获取漏洞列表
func GetVulnList(c *gin.Context) {
	type VulnRequest struct {
		VulnName string   `json:"vuln_name,omitempty" bson:"vuln_name,omitempty"`
		CveId    string   `json:"cve_id,omitempty" bson:"cve_id,omitempty"`
		Level    []string `json:"level,omitempty" bson:"level,omitempty"`
		Status   []string `json:"status,omitempty" bson:"status,omitempty"`
		Tag      []string `json:"tag,omitempty" bson:"tag,omitempty"`
		AgentId  string   `json:"agent_id,omitempty" bson:"agent_id,omitempty"`
	}
	levelMap := map[string]string{
		"1": LowLevel,
		"2": LowLevel,
		"3": MidLevel,
		"4": HighLevel,
		"5": DangerLevel,
	}

	// 绑定分页数据
	var pageRequest PageRequest
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

	// 拼接mongo查询语句(agent_vuln_info)
	agentVulnInfoFilter := make(map[string]interface{})
	if vulnRequest.AgentId != "" {
		agentVulnInfoFilter["agent_id"] = vulnRequest.AgentId
	}
	if vulnRequest.CveId != "" {
		agentVulnInfoFilter["cve_id"] = vulnRequest.CveId
	}
	if len(vulnRequest.Level) != 0 {
		agentVulnInfoFilter["level"] = MongoInside{Inside: vulnRequest.Level}
	}

	// 拼接mongo查询语句(vuln_info)
	vulnInfoFilter := make(map[string]interface{})
	if vulnRequest.VulnName != "" {
		vulnInfoFilter["title_cn"] = MongoRegex{Regex: vulnRequest.VulnName}
	}
	if len(vulnRequest.Tag) != 0 {
		for _, tag := range vulnRequest.Tag {
			if tag == HasEXP {
				vulnInfoFilter["has_payload"] = 1
			}
		}
		if !(len(vulnRequest.Tag) == 1 && vulnRequest.Tag[0] == HasEXP) {
			vulnInfoFilter["vuln_type_cn"] = MongoInside{Inside: vulnRequest.Tag}
		}
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	pageSearch := PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: nil, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo超级聚合查询
	var aggregateSearchList bson.A

	// 加入agent_vuln_info表的过滤条件
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": agentVulnInfoFilter})

	// 聚合查询，主要目的是vuln_id去重
	groupFilter := bson.M{"$group": bson.M{
		"_id":     "$vuln_id",
		"vuln_id": bson.M{"$first": "$vuln_id"},
		"status":  bson.M{"$addToSet": "$status"},
	}}
	aggregateSearchList = append(aggregateSearchList, groupFilter)

	// 连表查询，查询vuln_info表的信息
	aggregateSearchList = append(aggregateSearchList, bson.M{"$lookup": bson.M{
		"from":         "vuln_info",
		"localField":   "vuln_id",
		"foreignField": "id",
		"as":           "inventory_docs",
	}})

	// 加入vuln_info表查询的过滤条件
	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{
		"inventory_docs": MongoElem{Value: vulnInfoFilter},
	}})

	// 过滤漏洞状态
	statusList := make([]string, 0)

	if len(vulnRequest.Status) != 0 && vulnRequest.Status[0] == VulnStatusIgnored {
		statusList = append(statusList, VulnStatusUnProcessed)
	}
	if len(vulnRequest.Status) != 0 && vulnRequest.Status[0] == VulnStatusProcessed {

		statusList = append(statusList, VulnStatusUnProcessed)
		statusList = append(statusList, VulnStatusIgnored)
	}

	aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{
		"status": MongoInside{Inside: vulnRequest.Status},
	}})
	if len(statusList) != 0 {

		aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{
			"status": MongoNinside{Value: statusList},
		}})
	}

	// 聚合查询
	var dataResponse []AgentVulnInfo
	pageResponse, err := DBAggregatePaginate(
		collection,
		aggregateSearchList,
		pageSearch,
		func(cursor *mongo.Cursor) error {

			v := struct {
				VulnId        int64      `json:"vuln_id" bson:"vuln_id"`
				Status        []string   `json:"status" bson:"status"`
				InventoryDocs []VulnInfo `json:"inventory_docs" bson:"inventory_docs"`
			}{}
			_ = cursor.Decode(&v)

			var agentVulnInfo AgentVulnInfo
			agentVulnInfo.VulnId = v.VulnId

			// 生成漏洞状态
			agentVulnInfo.Status = VulnStatusProcessed
			for _, status := range v.Status {
				if status == VulnStatusUnProcessed {
					agentVulnInfo.Status = VulnStatusUnProcessed
					break
				}
				if status == VulnStatusIgnored {
					agentVulnInfo.Status = VulnStatusIgnored
				}
			}
			vulnInfo := v.InventoryDocs[0]
			if len(vulnInfo.VulnName) > 0 {
				agentVulnInfo.VulnName = vulnInfo.VulnName
			} else {
				agentVulnInfo.VulnName = vulnInfo.VulnNameEn
			}
			agentVulnInfo.CveId = vulnInfo.CveId
			agentVulnInfo.Level = levelMap[vulnInfo.Level]

			// 拼接tag
			var tag []string
			if len(vulnInfo.Cwe) != 0 {
				tag = append(tag, vulnInfo.Cwe)
			}
			if vulnInfo.IfExp == 1 {
				tag = append(tag, HasEXP)
			}
			agentVulnInfo.Tag = tag
			dataResponse = append(dataResponse, agentVulnInfo)
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

	// 绑定漏洞信息
	var vulnInfo VulnInfo
	id := c.Query("vuln_id")
	idInt, _ := strconv.Atoi(id)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	err := collection.FindOne(c, bson.M{"id": idInt}).Decode(&vulnInfo)
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 获取漏洞cpe信息
	var cpeInfo CpeInfo
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CpeInfoCollection)
	err = collection.FindOne(c, bson.M{"vuln_id": idInt}).Decode(&cpeInfo)
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 关联cpe信息
	vulnInfo.CpeName = cpeInfo.CpeName
	vulnInfo.CpeVersion = cpeInfo.CpeVersion

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
	if len(vulnInfo.VulnName) == 0 {
		vulnInfo.Descript = vulnInfo.DescriptEn
		vulnInfo.Suggest = vulnInfo.SuggestEn
	}

	common.CreateResponse(c, common.SuccessCode, vulnInfo)
}

// 获取漏洞影响资产列表
func VulnHostList(c *gin.Context) {

	// 返回的主机数据
	type responseStruct struct {
		HostName    string `json:"host_name" bson:"hostname"`
		IntranetIp  string `json:"intranet_ip" bson:"intranet_ip"`
		ExtranetIp  string `json:"extranet_ip" bson:"extranet_ip"`
		UpdateTime  int64  `json:"update_time" bson:"update_time"`
		CreateTime  int64  `json:"create_time" bson:"create_time"`
		ControlTime int64  `json:"control_time" bson:"control_time"`
		Status      string `json:"status" bson:"status"`
		AgentId     string `json:"agent_id" bson:"agent_id"`
	}

	// 绑定分页数据
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetTaskList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	// 绑定漏洞筛选数据
	request := struct {
		Status []string `json:"status" bson:"status"`
		VulnId int64    `json:"vuln_id" bson:"vuln_id"`
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
		searchFilter["status"] = MongoInside{Inside: request.Status}
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	pageSearch := PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// 获取漏洞信息
	var dataResponse []responseStruct
	agentIdList := make([]string, 0)

	agentIdMap := make(map[string]string)
	pageResponse, err := DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var response responseStruct
			err := cursor.Decode(&response)
			if err != nil {
				return err
			}
			dataResponse = append(dataResponse, response)
			_, ok := agentIdMap[response.AgentId]
			if !ok {
				agentIdList = append(agentIdList, response.AgentId)
				agentIdMap[response.AgentId] = ""
			}
			return nil
		},
	)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 获取主机信息
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cur, _ := collection.Find(c, bson.M{"agent_id": bson.M{"$in": agentIdList}})
	defer cur.Close(c)
	type agentStruct struct {
		AgentId      string   `json:"agent_id" bson:"agent_id"`
		HostName     string   `json:"host_name" bson:"hostname"`
		SourceIp     string   `json:"source_ip" bson:"source_ip"`
		ExtranetIpv4 []string `json:"extranet_ipv_4" bson:"extranet_ipv_4"`
		IntranetIpv4 []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	}
	var v agentStruct
	agentInfoMap := make(map[string]agentStruct)
	for cur.Next(c) {
		_ = cur.Decode(&v)
		agentInfoMap[v.AgentId] = v
	}

	// 关联主机信息和漏洞信息
	for i, data := range dataResponse {
		agentInfo, ok := agentInfoMap[data.AgentId]
		if ok {
			dataResponse[i].HostName = agentInfo.HostName
			if len(agentInfo.IntranetIpv4) > 0 {
				dataResponse[i].IntranetIp = agentInfo.IntranetIpv4[0]
			}
			if len(agentInfo.ExtranetIpv4) > 0 {
				dataResponse[i].ExtranetIp = agentInfo.ExtranetIpv4[0]
			}
		}
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
		updateRes, err := collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "control_time": time.Now().Unix()}})
		if err != nil && err != mongo.ErrNoDocuments {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		// 漏洞数量同步到心跳表
		var vulnNumInt int
		if request.AfterStatus == VulnStatusUnProcessed {
			vulnNum := updateRes.MatchedCount
			strInt64 := strconv.FormatInt(vulnNum, 10)
			vulnNumInt, _ = strconv.Atoi(strInt64)
		} else {
			vulnNumInt = 0
		}
		updateQuery := bson.M{"$set": bson.M{"risk.vuln": vulnNumInt}}
		ahCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		ahCol.UpdateOne(c, searchFilter, updateQuery)
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
			defer cur.Close(c)
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
			searchFilter["agent_id"] = MongoInside{Inside: agentList}
		}

		// 更新漏洞
		_, err = collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "control_time": time.Now().Unix()}})
		if err != nil && err != mongo.ErrNoDocuments {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		// 更新主机risk数据
		searchFilter = make(map[string]interface{})
		searchFilter["agent_id"] = MongoInside{Inside: agentList}
		var updateQuery bson.M
		if request.AfterStatus == VulnStatusUnProcessed {
			updateQuery = bson.M{"$inc": bson.M{"risk.vuln": 1}}
		} else {
			updateQuery = bson.M{"$inc": bson.M{"risk.vuln": -1}}
		}

		ahCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		ahCol.UpdateMany(c, searchFilter, updateQuery)
	}

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
	searchFilter["status"] = VulnStatusUnProcessed
	unprocessCount, err := collection.CountDocuments(c, searchFilter)
	if err != nil {
		unprocessCount = 0
	}

	// 拼接mongo查询语句
	searchFilter = make(map[string]interface{})
	if !request.IfAll {
		if len(request.VulnIdList) != 0 {
			searchFilter["vuln_id"] = MongoInside{Inside: request.VulnIdList}
		}
	}
	searchFilter["agent_id"] = request.AgentId
	searchFilter["status"] = request.BeforeStatus

	updateRes, err := collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus, "control_time": time.Now().Unix()}})
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 计算漏洞总数，并更新到主机心跳包中
	var newUnprocessCount int64
	if request.BeforeStatus == VulnStatusUnProcessed {
		newUnprocessCount = unprocessCount - updateRes.ModifiedCount
	}
	if request.AfterStatus == VulnStatusUnProcessed {
		newUnprocessCount = unprocessCount + updateRes.ModifiedCount
	}

	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)

	filterQuery := bson.M{"agent_id": request.AgentId}
	strInt64 := strconv.FormatInt(newUnprocessCount, 10)
	id16, _ := strconv.Atoi(strInt64)
	updateQuery := bson.M{"$set": bson.M{"risk.vuln": id16}}
	ahCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	ahCol.UpdateOne(c, filterQuery, updateQuery)

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
			searchFilter["vuln_id"] = MongoInside{Inside: request.VulnIdList}
		}
	}
	searchFilter["status"] = request.BeforeStatus

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	_, err = collection.UpdateMany(c, searchFilter, bson.M{"$set": bson.M{"status": request.AfterStatus}})
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}
