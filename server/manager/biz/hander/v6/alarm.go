package v6

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	dbtask "github.com/bytedance/Elkeid/server/manager/task"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
)

// ############################### Data Struct ###############################
type AlarmListRequest struct {
	Name        string   `json:"name"`
	Status      int      `json:"status"`
	LevelList   []string `json:"level"`
	TypeList    []string `json:"type"`
	DataType    string   `json:"data_type"`
	TimeStart   int64    `json:"time_start"`
	TimeEnd     int64    `json:"time_end"`
	AgentId     string   `json:"agent_id"`
	ClusterName string   `json:"cluster"`
}

type AlarmBriefData struct {
	AlarmId   string `json:"alarm_id"`
	AgentId   string `json:"agent_id"`
	Status    int    `json:"status"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Level     string `json:"level"`
	HostName  string `json:"alarm_hostname"`
	AlarmTime int64  `json:"alarm_time"`
}

type AlarmDetailDataBaseAgent struct {
	HostName string   `json:"hostname"`
	InnerIPs []string `json:"in_ip_list"`
	OuterIPs []string `json:"out_ip_list"`
	AgentId  string   `json:"agent_id"`
	Os       string   `json:"os"`
}

type AlarmDetailDataBaseAlarm struct {
	AlarmType  string `json:"alarm_type"`
	AlarmLevel string `json:"level"`
	Status     int    `json:"status"`
	UpdateTime int64  `json:"update_time"`
	Desc       string `json:"desc"`
	Suggest    string `json:"suggest"`
	Docker     string `json:"docker"`
}

type AlarmNewStatus struct {
	AlarmId     string `json:"alarm_id"`
	AlarmStatus int    `json:"alarm_status"`
}

type AlarmStatusUpdateRequest struct {
	Lists []AlarmNewStatus `json:"alarms"`
}

type AlarmStatusUpdateInfo struct {
	AlarmId string `json:"alarm_id"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
}

type AgentStatisticsReq struct {
	AgentId string `form:"agent_id"`
}

type AgentHbInfo struct {
	Platform        string   `json:"platform" bson:"platform"`
	PlatformFamily  string   `json:"platform_family" bson:"platform_family"`
	PlatformVersion string   `json:"platform_version" bson:"platform_version"`
	InnerIPv4       []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	OuterIPv4       []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
}

type AgentStatisticsInfo struct {
	Total            int `json:"alarm_total"`
	CriticalLevelNum int `json:"alarm_critical_num"`
	HighLevelNum     int `json:"alarm_high_num"`
	MediumLevelNum   int `json:"alarm_medium_num"`
	LowLevelNum      int `json:"alarm_low_num"`
	ProcessedNum     int `json:"alarm_processed_num"`
	WhiteListNum     int `json:"alarm_white_num"`
}

var AlarmTypeCnToEn map[string]string = map[string]string{
	"暴力破解": "bruteforce",
	"提权攻击": "privilege_escalation",
	"后门驻留": "persistent",
	"变形木马": "evasion",
	"恶意破坏": "purpose",
	"静态检测": "static_scan",
	"杀伤链":  "killchain",
}

// ############################### Variable ###############################
const (
	ALARM_LEVEL_CRITICAL string = "critical"
	ALARM_LEVEL_HIGH     string = "high"
	ALARM_LEVEL_MEDIUM   string = "medium"
	ALARM_LEVEL_LOW      string = "low"
)

const (
	ALARM_STAT_AGGREGATE_GROUP_ID    string = "_id"
	ALARM_STAT_AGGREGATE_GROUP_COUNT string = "count"
)

// ############################### Function ###############################
func GetAlarmList(c *gin.Context) {
	var pageRequest PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	var listReq AlarmListRequest
	err = c.BindJSON(&listReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	searchFilter := common.FilterQuery{
		Filter:    make([]common.FilterContent, 0),
		Condition: "$and",
	}

	if listReq.AgentId != "" {
		aid := common.FilterContent{
			Key: "agent_id",
			Rules: []common.FilterRule{
				{
					Operator: "$eq",
					Value:    listReq.AgentId,
				},
			},
			Condition: "$and",
		}
		searchFilter.Filter = append(searchFilter.Filter, aid)
	}

	if listReq.Name != "" {
		nid := common.FilterContent{
			Key: "SMITH_ALERT_DATA.RULE_INFO.RuleName",
			Rules: []common.FilterRule{
				{
					Operator: "$regex",
					Value:    listReq.Name,
				},
			},
			Condition: "$and",
		}
		searchFilter.Filter = append(searchFilter.Filter, nid)
	}

	/*
		if len(listReq.StatusList) > 0 {
			tmpList := []string{}
			for _, m := range listReq.StatusList {
				if len(m) > 0 {
					tmpList = append(tmpList, m)
				}
			}

			sid := common.FilterContent{
				Key: "__alarm_status",
				Rules: []common.FilterRule{
					{
						Operator: "$in",
						Value:    tmpList,
					},
				},
				Condition: "$and",
			}
			searchFilter.Filter = append(searchFilter.Filter, sid)
		}*/
	// status
	stid := common.FilterContent{
		Key: "__alarm_status",
		Rules: []common.FilterRule{
			{
				Operator: "$eq",
				Value:    listReq.Status,
			},
		},
		Condition: "$and",
	}
	searchFilter.Filter = append(searchFilter.Filter, stid)

	if len(listReq.LevelList) > 0 {
		tmpList := []string{}
		for _, l := range listReq.LevelList {
			if len(l) > 0 {
				tmpList = append(tmpList, l)
			}
		}

		lid := common.FilterContent{
			Key: "SMITH_ALERT_DATA.RULE_INFO.HarmLevel",
			Rules: []common.FilterRule{
				{
					Operator: "$in",
					Value:    tmpList,
				},
			},
			Condition: "$and",
		}
		searchFilter.Filter = append(searchFilter.Filter, lid)
	}

	if len(listReq.TypeList) > 0 {
		tmpList := []string{}
		for _, t := range listReq.TypeList {
			if len(t) > 0 {
				tmpList = append(tmpList, t)
			}
		}

		tid := common.FilterContent{
			Key: "alert_type_us",
			Rules: []common.FilterRule{
				{
					Operator: "$in",
					Value:    tmpList,
				},
			},
			Condition: "$and",
		}
		searchFilter.Filter = append(searchFilter.Filter, tid)
	}

	if listReq.DataType != "" {
		did := common.FilterContent{
			Key: "data_type",
			Rules: []common.FilterRule{
				{
					Operator: "$eq",
					Value:    listReq.DataType,
				},
			},
			Condition: "$and",
		}
		searchFilter.Filter = append(searchFilter.Filter, did)
	}

	if (listReq.TimeStart > 0) && (listReq.TimeEnd > 0) {
		timeStart := time.Unix(listReq.TimeStart, 0).Format("2006-01-02 15:04")
		timeEnd := time.Unix(listReq.TimeEnd, 0).Format("2006-01-02 15:04")

		ts := common.FilterContent{
			Key: "__insert_time",
			Rules: []common.FilterRule{
				{
					Operator: "$time",
					Value: map[string]string{
						"start": timeStart,
						"end":   timeEnd,
					},
				},
			},
			Condition: "$and",
		}
		searchFilter.Filter = append(searchFilter.Filter, ts)
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	pageSearch := PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter: bson.M{
			"$and": bson.A{
				searchFilter.Transform(),
				bson.M{"__checked": true, "__hit_wl": false},
			},
		},
		Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default sort value
		pageSearch.Sorter = bson.M{"__insert_time": -1}
	}

	var dataResponse []AlarmBriefData
	pageResponse, err := DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var rawData AlarmDbData
			err := cursor.Decode(&rawData)
			if err != nil {
				ylog.Errorf("GetAlarmList", err.Error())
				return err
			}
			oneAlarm := AlarmBriefData{
				AlarmId:   rawData.Id,
				AgentId:   rawData.AgentId,
				HostName:  rawData.HostName,
				Status:    rawData.Status,
				Type:      rawData.AlertTypeUs,
				Level:     rawData.Info.RuleInfo.HarmLevel,
				Name:      rawData.Info.RuleInfo.RuleName,
				AlarmTime: rawData.InsertTime,
			}
			dataResponse = append(dataResponse, oneAlarm)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetAlarmList", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

func UpdateAlarmStatus(c *gin.Context) {
	var upReq AlarmStatusUpdateRequest
	// var agList []string = []string{}
	err := c.BindJSON(&upReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	res := make([]AlarmStatusUpdateInfo, 0, len(upReq.Lists))
	writes := make([]mongo.WriteModel, 0, len(upReq.Lists))
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)

	for _, v := range upReq.Lists {
		tmp := AlarmStatusUpdateInfo{
			AlarmId: v.AlarmId,
			Code:    0,
			Msg:     "ok",
		}

		objId, err := primitive.ObjectIDFromHex(v.AlarmId)
		if err != nil {
			tmp.Code = 1
			tmp.Msg = err.Error()
		} else {
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"_id": objId}).
				SetUpdate(bson.M{"$set": bson.M{"__alarm_status": v.AlarmStatus, "__update_time": time.Now().Unix()}}).
				SetUpsert(false)
			writes = append(writes, model)

			// get agent id from alarm
			/*
				var rawData AlarmDbData
				queryJs := bson.M{"_id": objId}
				oneRes := col.FindOne(c, queryJs)
				err = oneRes.Decode(&rawData)
				if err == nil {
					agList = append(agList, rawData.AgentId)
				} else {
					ylog.Errorf("Get agent id from alarm table error", err.Error())
				}*/
		}

		res = append(res, tmp)
	}
	if len(writes) > 0 {
		_, err = col.BulkWrite(c, writes, writeOption)
		if err != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	// update asset info
	/*
		for _, a := range agList {
			DelOneAlarmForAgentHb(c, a)
		}*/

	CreateResponse(c, common.SuccessCode, res)
}

func MakeAlarmDetail(src *AlarmDbData, dst *AlarmDetailData) {

	var hasCommAlarm bool = true

	dst.DataType = src.DataType

	// base agent
	dst.BaseAgent.HostName = src.HostName
	dst.BaseAgent.AgentId = src.AgentId
	dst.BaseAgent.OuterIPs = []string{}
	dst.BaseAgent.InnerIPs = []string{}
	if len(src.ExIpv4List) > 0 {
		outTmp := strings.Split(src.ExIpv4List, ",")
		if len(outTmp) > 0 {
			dst.BaseAgent.OuterIPs = outTmp
		}
	}

	if len(src.InIpv4List) > 0 {
		inTmp := strings.Split(src.InIpv4List, ",")
		if len(inTmp) > 0 {
			dst.BaseAgent.InnerIPs = inTmp
		}
	}

	// base alarm
	dst.BaseAlarm.AlarmLevel = src.Info.RuleInfo.HarmLevel
	dst.BaseAlarm.AlarmType = src.AlertTypeUs
	dst.BaseAlarm.Status = src.Status
	// dst.BaseAlarm.UpdateTime = src.UpdateTime
	dst.BaseAlarm.UpdateTime = src.InsertTime
	dst.BaseAlarm.Desc = src.Info.RuleInfo.Desc
	dst.BaseAlarm.Suggest = src.Suggestion
	dst.BaseAlarm.Docker = src.InDocker

	// comm alarm
	switch src.DataType {
	case ALARM_DATA_TYPE_700:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_701:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_702:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_703:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_4000:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_6001:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_6002:
		hasCommAlarm = false
	case ALARM_DATA_TYPE_KC:
		hasCommAlarm = false
	default:
		hasCommAlarm = true
	}

	if hasCommAlarm {
		dst.CommAlarm.Pid = src.Pid
		dst.CommAlarm.Exec = src.Exec
		dst.CommAlarm.Argv = src.Argv
		dst.CommAlarm.Ppid = src.Ppid
		dst.CommAlarm.Ppid_argv = src.PpidArgv
		dst.CommAlarm.Pgid = src.Pgid
		dst.CommAlarm.Pgid_argv = src.PgidArgv
		dst.CommAlarm.Username = src.UserName
	}

	if src.DataType == ALARM_DATA_TYPE_KC {
		CopyDataTypeKC(dst, src)
	}

	if src.DataType == ALARM_DATA_TYPE_59 {
		dst.Plus59.PidTree = src.PidTree
		dst.Plus59.SocketPid = src.SocketPid
		dst.Plus59.SocketArgv = src.SocketArgv
		dst.Plus59.Ssh = src.Ssh
		dst.Plus59.SshInfo = src.SshInfo
		dst.Plus59.Uid = src.Uid
		if src.ConnInfo != "" {
			dst.Plus59.SshInfo = src.ConnInfo
		} else {
			dst.Plus59.SshInfo = fmt.Sprintf("%s:%s -> %s:%s",
				src.Sip, src.Sport, src.Dip, src.Dport)
		}
	}

	if src.DataType == ALARM_DATA_TYPE_42 {
		dst.Plus42.PidTree = src.PidTree
		if src.ConnInfo != "" {
			dst.Plus42.SshInfo = src.ConnInfo
		} else {
			dst.Plus42.SshInfo = fmt.Sprintf("%s:%s -> %s:%s",
				src.Sip, src.Sport, src.Dip, src.Dport)
		}
	}

	if src.DataType == ALARM_DATA_TYPE_49 {
		dst.Plus49.PidTree = src.PidTree
		dst.Plus49.Sport = src.Sport
	}

	if src.DataType == ALARM_DATA_TYPE_101 {
		dst.Plus101.PtraceRequest = src.PtraceRequest
		dst.Plus101.TargeId = src.TargeId
	}

	if src.DataType == ALARM_DATA_TYPE_601 {
		dst.Plus601.Query = src.Query
	}

	if src.DataType == ALARM_DATA_TYPE_602 {
		dst.Plus602.FilePath = src.FilePath
	}

	if src.DataType == ALARM_DATA_TYPE_603 {
		dst.Plus603.ModInfo = src.ModInfo
	}

	if src.DataType == ALARM_DATA_TYPE_604 {
		dst.Plus604.OldUid = src.OldUid
		dst.Plus604.PidTree = src.PidTree
		dst.Plus604.OldUserName = src.OldUserName
	}

	if src.DataType == ALARM_DATA_TYPE_700 {
		dst.Plus700.ModuleName = src.ModuleName
	}

	if src.DataType == ALARM_DATA_TYPE_701 {
		dst.Plus701.ModuleName = src.ModuleName
		dst.Plus701.SyscallNumber = src.SyscallNumber
	}

	if src.DataType == ALARM_DATA_TYPE_702 {
		dst.Plus702.ModuleName = src.ModuleName
	}

	if src.DataType == ALARM_DATA_TYPE_703 {
		dst.Plus703.InterruptNumber = src.InterruptNumber
		dst.Plus703.ModuleName = src.ModuleName
	}

	if src.DataType == ALARM_DATA_TYPE_3004 {
		dst.Plus3004.Path = src.Path
	}

	if src.DataType == ALARM_DATA_TYPE_4000 {
		dst.Plus4000.Sip = src.Sip
		dst.Plus4000.Sport = src.Sport
		dst.Plus4000.Types = src.Types
		dst.Plus4000.User = src.User
	}

	if src.DataType == ALARM_DATA_TYPE_6001 {
		CopyDataType6001(dst, src)
	}

	if src.DataType == ALARM_DATA_TYPE_6002 {
		CopyDataType6002(dst, src)
	}
}

func GetAgentOsVer(c *gin.Context, aid string) string {
	var retStr string = ""
	var oneHb AgentHbInfo = AgentHbInfo{}
	if aid == "" {
		return retStr
	}

	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	queryJs := bson.M{"agent_id": aid}
	err := hbCol.FindOne(c, queryJs).Decode(&oneHb)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			ylog.Errorf("GetAgentOsVer", "get hb error %s", err.Error())
		}
	} else {
		retStr = fmt.Sprintf("%s %s", oneHb.PlatformFamily, oneHb.PlatformVersion)
	}

	return retStr
}

func GetOneAlarm(c *gin.Context) {
	var rsp AlarmDetailData
	alarmId := c.Param("aid")
	if alarmId == "" {
		qErr := errors.New("alarm_id is empty")
		CreateResponse(c, common.ParamInvalidErrorCode, qErr.Error())
		return
	}

	oid, oErr := primitive.ObjectIDFromHex(alarmId)
	if oErr != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, oErr.Error())
		return
	}

	// query data
	var oneAlarm AlarmDbData = AlarmDbData{}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	queryJS := bson.M{"_id": bson.M{"$eq": oid}}
	err := col.FindOne(c, queryJS).Decode(&oneAlarm)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// trans dbdata to apidata
	MakeAlarmDetail(&oneAlarm, &rsp)

	// get os version
	if rsp.DataType == "" {
		GetAgentDetail(c, oneAlarm.AgentId, &rsp.BaseAgent)
	} else {
		rsp.BaseAgent.Os = GetAgentOsVer(c, oneAlarm.AgentId)
	}

	CreateResponse(c, common.SuccessCode, rsp)
}

func GetAlarmStat(c *gin.Context) {
	var req AgentStatisticsReq
	var rsp AgentStatisticsInfo = AgentStatisticsInfo{
		Total: 0, CriticalLevelNum: 0, HighLevelNum: 0,
		MediumLevelNum: 0, LowLevelNum: 0,
		ProcessedNum: 0, WhiteListNum: 0,
	}
	err := c.BindQuery(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	ylog.Infof("alarm stat", "agentid %s", req.AgentId)
	var handleQuery primitive.M
	var whiteQuery primitive.M
	var alarmMatchQuery primitive.D
	if req.AgentId != "" {
		whiteCondision := []bson.M{}
		whiteNoAgentId := bson.M{"filter.key": bson.M{"$eq": "agent_id"}, "filter.rules.value": req.AgentId}
		whiteWithAgent := bson.M{"filter.key": bson.M{"$ne": "agent_id"}}
		whiteCondision = append(whiteCondision, whiteWithAgent)
		whiteCondision = append(whiteCondision, whiteNoAgentId)
		handleQuery = bson.M{"agent_id": req.AgentId, "__alarm_status": bson.M{"$ne": 0}, "__hit_wl": false}
		whiteQuery = bson.M{"$or": whiteCondision}
		alarmMatchQuery = bson.D{primitive.E{Key: "$match", Value: bson.D{
			primitive.E{Key: "agent_id", Value: req.AgentId},
			primitive.E{Key: "__alarm_status", Value: 0},
			primitive.E{Key: "__hit_wl", Value: false},
		}}}
	} else {
		handleQuery = bson.M{"__alarm_status": bson.M{"$ne": 0}, "__hit_wl": false}
		whiteQuery = bson.M{}
		alarmMatchQuery = bson.D{primitive.E{Key: "$match", Value: bson.D{
			primitive.E{Key: "__alarm_status", Value: 0},
			primitive.E{Key: "__hit_wl", Value: false},
		}}}
	}

	alarmGroupQuery := bson.D{primitive.E{Key: "$group", Value: bson.D{
		primitive.E{Key: ALARM_STAT_AGGREGATE_GROUP_ID, Value: "$SMITH_ALERT_DATA.RULE_INFO.HarmLevel"},
		primitive.E{Key: ALARM_STAT_AGGREGATE_GROUP_COUNT, Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
	}}}
	// alarmProjectQuery := bson.D{{"$project", bson.D{{"_id", 0}, {"SMITH_ALERT_DATA.RULE_INFO.HarmLevel", 1}}}}
	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	whiteCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubWhiteListCollectionV1)

	// level num
	// retCur, aErr := alarmCol.Aggregate(c, mongo.Pipeline{alarmMatchQuery, alarmGroupQuery, alarmProjectQuery})
	retCur, aErr := alarmCol.Aggregate(c, mongo.Pipeline{alarmMatchQuery, alarmGroupQuery})
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, aErr.Error())
		return
	}

	defer retCur.Close(c)
	results := []bson.M{}
	rErr := retCur.All(c, &results)
	if rErr != nil {
		CreateResponse(c, common.DBOperateErrorCode, rErr.Error())
		return
	}

	for _, r := range results {
		sx, sOk := r[ALARM_STAT_AGGREGATE_GROUP_ID].(string)
		ix, iOk := r[ALARM_STAT_AGGREGATE_GROUP_COUNT].(int32)
		if !sOk || !iOk {
			continue
		}

		switch sx {
		case ALARM_LEVEL_CRITICAL:
			rsp.CriticalLevelNum = rsp.CriticalLevelNum + int(ix)
		case ALARM_LEVEL_HIGH:
			rsp.HighLevelNum = rsp.HighLevelNum + int(ix)
		case ALARM_LEVEL_MEDIUM:
			rsp.MediumLevelNum = rsp.MediumLevelNum + int(ix)
		case ALARM_LEVEL_LOW:
			rsp.LowLevelNum = rsp.LowLevelNum + int(ix)
		}
	}

	// handle num
	handleNum, hErr := alarmCol.CountDocuments(c, handleQuery)
	if hErr != nil {
		CreateResponse(c, common.DBOperateErrorCode, hErr.Error())
		return
	}

	// white policy num
	whiteNum, wErr := whiteCol.CountDocuments(c, whiteQuery)
	if wErr != nil {
		CreateResponse(c, common.DBOperateErrorCode, wErr.Error())
		return
	}

	rsp.Total = rsp.CriticalLevelNum + rsp.HighLevelNum + rsp.MediumLevelNum + rsp.LowLevelNum
	rsp.ProcessedNum = int(handleNum)
	rsp.WhiteListNum = int(whiteNum)
	CreateResponse(c, common.SuccessCode, rsp)
}

func AddOneAlarm(c *gin.Context) {
	var newAlarm map[string]interface{}
	err := c.BindJSON(&newAlarm)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	//0-->未处理
	newAlarm["__alarm_status"] = 0
	newAlarm["__update_time"] = time.Now().Unix()
	newAlarm["__insert_time"] = time.Now().Unix()
	newAlarm["__checked"] = false
	newAlarm["__hit_wl"] = false

	// write to db
	dbtask.HubAlarmAsyncWrite(newAlarm)

	// update agent alarm count
	/*agid, aok := newAlarm["agent_id"].(string)
	if aok {
		AddOneAlarmForAgentHb(c, agid)
	}*/

	// send response
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func AddOneAlarmForAgentHb(c *gin.Context, agent_id string) {
	filterQuery := bson.M{"agent_id": agent_id}
	updateQuery := bson.M{"$inc": bson.M{"risk.alarm": 1}}
	ahCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	_, err := ahCol.UpdateOne(c, filterQuery, updateQuery)
	if err != nil {
		ylog.Errorf("AddOneAlarmForAgentHb", "error %s", err.Error())
	}
}

func DelOneAlarmForAgentHb(c *gin.Context, agent_id string) {
	filterQuery := bson.M{"agent_id": agent_id}
	updateQuery := bson.M{"$inc": bson.M{"risk.alarm": -1}}
	ahCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	_, err := ahCol.UpdateOne(c, filterQuery, updateQuery)
	if err != nil {
		ylog.Errorf("AddOneAlarmForAgentHb", "error %s", err.Error())
	}
}

func GetAgentDetail(c *gin.Context, aid string, dst *AlarmDetailDataBaseAgent) error {
	var oneHb AgentHbInfo = AgentHbInfo{}
	if aid == "" {
		return nil
	}

	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	queryJs := bson.M{"agent_id": aid}
	err := hbCol.FindOne(c, queryJs).Decode(&oneHb)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			ylog.Errorf("GetAgentOsVer", "get hb error %s", err.Error())
			return err
		}
	}

	// update detail
	dst.Os = fmt.Sprintf("%s %s", oneHb.PlatformFamily, oneHb.PlatformVersion)
	dst.InnerIPs = make([]string, len(oneHb.InnerIPv4))
	dst.OuterIPs = make([]string, len(oneHb.OuterIPv4))
	copy(dst.InnerIPs, oneHb.InnerIPv4)
	copy(dst.OuterIPs, oneHb.OuterIPv4)

	return nil
}

func GetOneAlarmRaw(c *gin.Context) {
	var rsp AlarmRawData
	alarmId := c.Param("aid")
	if alarmId == "" {
		qErr := errors.New("alarm_id is empty")
		CreateResponse(c, common.ParamInvalidErrorCode, qErr.Error())
		return
	}

	oid, oErr := primitive.ObjectIDFromHex(alarmId)
	if oErr != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, oErr.Error())
		return
	}

	// query data
	var raw map[string]interface{}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	queryJS := bson.M{"_id": bson.M{"$eq": oid}}
	err := col.FindOne(c, queryJS).Decode(&raw)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// get os version
	rsp.RawData = raw

	CreateResponse(c, common.SuccessCode, rsp)
}
