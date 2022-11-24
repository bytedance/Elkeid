package v6

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/internal/alarm"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
)

// const

const (
	RadfnAlarmStatus     = "__alarm_status"
	RadfnAlarmHitWhite   = "__hit_wl"
	RadfnAlarmWhiteCheck = "__checked"

	RadfnEventName   = "event_name"
	RadfnAgentId     = "agent_id"
	RadfnHostname    = "hostname"
	RadfnHostInIpv4  = "in_ipv4_list"
	RadfnHostOutIpv4 = "ex_ipv4_list"
	RadfnHostInIpv6  = "in_ipv6_list"
	RadfnHostOutIpv6 = "ex_ipv6_list"
	RadfnInsertTime  = "__insert_time"
	RadfnRuleName    = "rule_name"
	RadfnLevel       = "HarmLevel"
	RadfnAlertType   = "alert_type_us"
	RadfnReasonHash  = "stack_trace_hash"
)

// function

func RaspAddOneAlarm(c *gin.Context) {
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
	newAlarm["__checker"] = ""
	newAlarm["__hit_wl"] = false
	newAlarm["__handler_user"] = ""
	alarmID := xid.New().String()
	newAlarm["alarm_id"] = alarmID

	// write to db
	dbtask.RaspAlarmAsyncWrite(newAlarm)

	// send response
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func CombineRaspAlarmCondition(cond *RaspAlarmQueryFilter, isQueryWhite bool) bson.A {
	searchContent := make(bson.A, 0, 50)

	if cond.AgentId != "" {
		adFl := bson.M{RadfnAgentId: cond.AgentId}
		searchContent = append(searchContent, adFl)
	}

	if cond.Name != "" {
		enFl := bson.M{RadfnRuleName: bson.M{"$regex": cond.Name}}
		searchContent = append(searchContent, enFl)
	}

	if cond.Hostname != "" {
		hnFl := bson.M{RadfnHostname: bson.M{"$regex": cond.Hostname}}
		searchContent = append(searchContent, hnFl)
	}

	if len(cond.LevelList) > 0 {
		lvFl := bson.M{RadfnLevel: bson.M{
			"$in": cond.LevelList,
		}}
		searchContent = append(searchContent, lvFl)
	}

	if len(cond.StatusList) > 0 {
		stFl := bson.M{RadfnAlarmStatus: bson.M{
			"$in": cond.StatusList,
		}}
		searchContent = append(searchContent, stFl)
	}

	if cond.StartTime > 0 {
		etFl := bson.M{RadfnInsertTime: bson.M{
			"$gte": cond.StartTime,
		}}
		searchContent = append(searchContent, etFl)
	}

	if cond.EndTime > 0 {
		etFl := bson.M{RadfnInsertTime: bson.M{
			"$lte": cond.EndTime,
		}}
		searchContent = append(searchContent, etFl)
	}

	if len(cond.TypeList) > 0 {
		tgFl := bson.M{RadfnAlertType: bson.M{
			"$in": cond.TypeList,
		}}
		searchContent = append(searchContent, tgFl)
	}

	if cond.Ip != "" {
		ipFl := bson.M{"$or": bson.A{
			bson.M{RadfnHostInIpv4: bson.M{"$regex": cond.Ip}},
			bson.M{RadfnHostOutIpv4: bson.M{"$regex": cond.Ip}},
			bson.M{RadfnHostInIpv6: bson.M{"$regex": cond.Ip}},
			bson.M{RadfnHostOutIpv6: bson.M{"$regex": cond.Ip}},
		}}

		searchContent = append(searchContent, ipFl)
	}

	if cond.EventId != "" {
		eiFl := bson.M{alarm.AdfnEventId: cond.EventId}
		searchContent = append(searchContent, eiFl)
	}

	if cond.EventName != "" {
		etFl := bson.M{RadfnEventName: bson.M{"$regex": cond.EventName}}
		searchContent = append(searchContent, etFl)
	}

	if cond.EventReason != "" {
		erFl := bson.M{"$or": bson.A{
			bson.M{RadfnReasonHash: bson.M{"$regex": cond.EventReason}},
		}}

		searchContent = append(searchContent, erFl)
	}

	// default filter whitelist alarm
	wtFl := bson.M{RadfnAlarmHitWhite: isQueryWhite, RadfnAlarmWhiteCheck: true}
	searchContent = append(searchContent, wtFl)

	return searchContent
}

func GetAlarmListForRasp(c *gin.Context) {
	GetAlarmList(c, alarm.AlarmTypeRasp)
}

func MultiUpdateRaspAlarmStatus(c *gin.Context) {
	var upManyReq RaspAlarmStatusUpdateRequest
	var agList []string
	err := c.BindJSON(&upManyReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// get username
	user, userOk := c.Get("user")
	if !userOk {
		CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user info")
		return
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspAlarmCollectionV1)

	// query alarm id
	if upManyReq.AlarmIdList != nil {
		agList = append(agList, *upManyReq.AlarmIdList...)
	} else if upManyReq.Conditions != nil {
		alarmManyQueryCont := CombineRaspAlarmCondition(upManyReq.Conditions, false)
		alarmManyQuery := bson.M{
			"$and": alarmManyQueryCont,
		}
		alarmManyCur, aErr := col.Find(c, alarmManyQuery)
		if aErr != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		var manayRes []AlarmDbData
		aErr = alarmManyCur.All(c, &manayRes)
		if aErr != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		for _, one := range manayRes {
			agList = append(agList, one.Id)
		}
	}

	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	update_time := time.Now().Unix()

	res := make([]RaspAlarmStatusUpdateItem, 0, len(agList))
	writes := make([]mongo.WriteModel, 0, len(agList))
	if len(agList) > 0 {
		for _, v := range agList {
			tmp := RaspAlarmStatusUpdateItem{
				AlarmId: v,
				Code:    0,
				Msg:     "ok",
			}

			objId, err := primitive.ObjectIDFromHex(v)
			if err != nil {
				tmp.Code = 1
				tmp.Msg = err.Error()
			} else {
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"_id": objId}).
					SetUpdate(bson.M{"$set": bson.M{"__alarm_status": upManyReq.NewStatus,
						"__update_time": update_time, "__handler_user": user}}).
					SetUpsert(false)
				writes = append(writes, model)
			}

			res = append(res, tmp)
		}
	} else {
		// update all
		allModel := mongo.NewUpdateOneModel().
			SetUpdate(bson.M{"$set": bson.M{"__alarm_status": upManyReq.NewStatus,
				"__update_time": update_time, "__handler_user": user}}).
			SetUpsert(false)
		writes = append(writes, allModel)
	}

	if len(writes) > 0 {
		_, err = col.BulkWrite(c, writes, writeOption)
		if err != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}

	CreateResponse(c, common.SuccessCode, res)
}

func GetRaspAlarmStat(c *gin.Context) {
	var req RaspAlarmStatisticsRequest
	var rsp = RaspAlarmStatistics{
		Total:            0,
		CriticalLevelNum: 0, HighLevelNum: 0,
		MediumLevelNum: 0, LowLevelNum: 0,
		ProcessedNum: 0, WhiteListNum: 0,
	}
	err := c.BindQuery(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	// ylog.Infof("alarm stat", "agentid %s", req.AgentId)
	var handleQuery primitive.M
	var whiteQuery primitive.M
	var alarmMatchQuery primitive.D
	if req.AgentId != "" {
		var whiteCondision []bson.M
		whiteNoAgentId := bson.M{"filter.key": bson.M{"$eq": "agent_id"}, "filter.rules.value": req.AgentId}
		whiteWithAgent := bson.M{"filter.key": bson.M{"$ne": "agent_id"}}
		whiteCondision = append(whiteCondision, whiteWithAgent)
		whiteCondision = append(whiteCondision, whiteNoAgentId)
		handleQuery = bson.M{RadfnAgentId: req.AgentId, RadfnAlarmStatus: bson.M{"$ne": 0}, RadfnAlarmHitWhite: false}
		whiteQuery = bson.M{"$or": whiteCondision}
		alarmMatchQuery = bson.D{primitive.E{Key: "$match", Value: bson.D{
			primitive.E{Key: "agent_id", Value: req.AgentId},
			primitive.E{Key: RadfnAlarmStatus, Value: 0},
			primitive.E{Key: RadfnAlarmHitWhite, Value: false},
		}}}
	} else {
		handleQuery = bson.M{RadfnAlarmStatus: bson.M{"$ne": 0}, RadfnAlarmHitWhite: false}
		whiteQuery = bson.M{}
		alarmMatchQuery = bson.D{primitive.E{Key: "$match", Value: bson.D{
			primitive.E{Key: RadfnAlarmStatus, Value: 0},
			primitive.E{Key: RadfnAlarmHitWhite, Value: false},
		}}}
	}

	alarmGroupQuery := bson.D{primitive.E{Key: "$group", Value: bson.D{
		primitive.E{Key: ALARM_STAT_AGGREGATE_GROUP_ID, Value: "$SMITH_ALERT_DATA.RULE_INFO.HarmLevel"},
		primitive.E{Key: ALARM_STAT_AGGREGATE_GROUP_COUNT, Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
	}}}
	// alarmProjectQuery := bson.D{{"$project", bson.D{{"_id", 0}, {"SMITH_ALERT_DATA.RULE_INFO.HarmLevel", 1}}}}

	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspAlarmCollectionV1)
	whiteCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspAlarmWhiteV1)

	// level num
	// retCur, aErr := alarmCol.Aggregate(c, mongo.Pipeline{alarmMatchQuery, alarmGroupQuery, alarmProjectQuery})

	retCur, aErr := alarmCol.Aggregate(c, mongo.Pipeline{alarmMatchQuery, alarmGroupQuery})
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, aErr.Error())
		return
	}

	defer func() {
		_ = retCur.Close(c)
	}()
	var results []bson.M
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
		case alarm.AlarmLevelCritical:
			rsp.CriticalLevelNum = rsp.CriticalLevelNum + int(ix)
		case alarm.AlarmLevelHigh:
			rsp.HighLevelNum = rsp.HighLevelNum + int(ix)
		case alarm.AlarmLevelMedium:
			rsp.MediumLevelNum = rsp.MediumLevelNum + int(ix)
		case alarm.AlarmLevelLow:
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

	// alarm type distributed

	// send response
	CreateResponse(c, common.SuccessCode, rsp)
}

func ExportRaspAlarmListData(c *gin.Context) {
	var exportReq RaspAlarmExportDataRequest
	var agList []string
	err := c.BindJSON(&exportReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspAlarmCollectionV1)

	// query alarm id
	if exportReq.AlarmIdList != nil {
		agList = append(agList, *exportReq.AlarmIdList...)
	} else if exportReq.Conditions != nil {
		alarmManyQueryCont := CombineRaspAlarmCondition(exportReq.Conditions, false)
		alarmManyQuery := bson.M{
			"$and": alarmManyQueryCont,
		}
		alarmManyCur, aErr := col.Find(c, alarmManyQuery)
		if aErr != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		var manayRes []AlarmDbData
		aErr = alarmManyCur.All(c, &manayRes)
		if aErr != nil {
			CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		for _, one := range manayRes {
			agList = append(agList, one.Id)
		}
	}

	var alarmDetailDataHeaders = common.MongoDBDefs{
		{Key: "rule_name", Header: "rule_name"},
		{Key: "alert_type_us", Header: "type"},
		{Key: "HarmLevel", Header: "level"},
		{Key: "__alarm_status", Header: "status"},
		{Key: "hostname", Header: "hostname"},
		{Key: "event_name", Header: "event_name"},
		{Key: "__insert_time", Header: "alarm_time"},
	}

	idList := bson.A{}
	for _, one := range agList {
		if oid, err := primitive.ObjectIDFromHex(one); err == nil {
			idList = append(idList, oid)
		}
	}

	filename := "Exported-RaspAlarm"
	common.ExportFromMongoDB(c, col, bson.M{"_id": bson.M{"$in": idList}}, alarmDetailDataHeaders, filename)
}

func GetAlarmSummaryInfoForRasp(c *gin.Context) {
	GetAlarmSummaryInfo(c, alarm.AlarmTypeRasp)
}

func GetAlarmFilterByWhiteForRasp(c *gin.Context) {
	GetAlarmFilterByWhite(c, alarm.AlarmTypeRasp)
}
