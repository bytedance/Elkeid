package alarm

import (
	"context"
	"errors"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// data struct
type AlarmOverviewStat struct {
	CriticalNum int64 `json:"critical_num"`
	HighNum     int64 `json:"high_num"`
	MediumNum   int64 `json:"medium_num"`
	LowNum      int64 `json:"low_num"`
	TotalNum    int64 `json:"total_num"`
}

type AlarmUnhandleStatusAggresOut struct {
	Level string `json:"level" bson:"level"`
	Count int64  `json:"count" bson:"count"`
}

type AlarmOverviewDayTrend struct {
	DayTime              int64 `json:"day"`
	UnhandleAlarmNum     int64 `json:"unhandle_alarm_num"`
	HidsUnhandleAlarmNum int64 `json:"hids_unhandle_alarm_num"`
	RaspUnhandleAlarmNum int64 `json:"rasp_unhandle_alarm_num"`
	KubeUnhandleAlarmNum int64 `json:"kube_unhandle_alarm_num"`
}

type AlarmOverviewInfo struct {
	Total            int `json:"alarm_total"`
	CriticalLevelNum int `json:"alarm_critical_num"`
	HighLevelNum     int `json:"alarm_high_num"`
	MediumLevelNum   int `json:"alarm_medium_num"`
	LowLevelNum      int `json:"alarm_low_num"`
	ProcessedNum     int `json:"alarm_processed_num"`
	WhiteListNum     int `json:"alarm_white_num"`
}

// function
func GetAlarmDayStatDayTimeIndex(inTime int64, diff int) int64 {
	oneDaySec := int64(3600 * 24)
	timeDiff := inTime % oneDaySec
	timeIndex := inTime - timeDiff + int64(diff)*oneDaySec
	return timeIndex
}

func updateAlarmStatForDay(ctx context.Context, alarmType string) error {
	alarmColName, aErr := getAlarmCollectName(alarmType)
	if aErr != nil {
		return aErr
	}

	statColName, sErr := getAlarmStatCollectionName(alarmType)
	if sErr != nil {
		return sErr
	}

	// get today time
	nowTime := time.Now().Unix()
	timeIndex := GetAlarmDayStatDayTimeIndex(nowTime, 0)

	// query num
	unhandleQueryJs := bson.M{"__alarm_status": 0, "__hit_wl": false}
	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmColName)
	unhandleNum, cErr := alarmCol.CountDocuments(ctx, unhandleQueryJs)
	if cErr != nil {
		return cErr
	}

	newStat := AlarmDailyStatInfo{
		DayTime:     timeIndex,
		UnhandleNum: unhandleNum,
		UpdateTime:  nowTime,
	}

	// update stat
	statCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(statColName)
	option := &options.UpdateOptions{}
	option.SetUpsert(true)
	updateFilter := bson.M{"daytime": timeIndex}
	setValue := bson.M{"$set": newStat}
	_, cErr = statCol.UpdateOne(ctx, updateFilter, setValue, option)
	if cErr != nil {
		return cErr
	}

	return nil
}

func alarmPeriodicStatisticsWorker() {
	for {
		runCtx := context.Background()
		var err error

		// update alarm stat
		err = updateAlarmStatForDay(runCtx, AlarmTypeHids)
		if err != nil {
			ylog.Errorf("updateAlarmStatForDay for hids error", err.Error())
		}

		err = updateAlarmStatForDay(runCtx, AlarmTypeRasp)
		if err != nil {
			ylog.Errorf("updateAlarmStatForDay for rasp error", err.Error())
		}

		err = updateAlarmStatForDay(runCtx, AlarmTypeKube)
		if err != nil {
			ylog.Errorf("updateAlarmStatForDay for kube error", err.Error())
		}

		time.Sleep(60 * time.Second)
	}
}

func QueryAlarmOverview(ctx context.Context, alarmType string, agentID string, clusterID string, data *AlarmOverviewInfo) error {
	var handleQuery primitive.M
	var whiteQuery primitive.M
	var alarmMatchQuery primitive.D

	if data == nil {
		return errors.New("empty AlarmOverviewInfo for QueryAlarmOverview")
	}

	if agentID != "" {
		var whiteCondision []bson.M
		whiteNoAgentId := bson.M{"filter.key": bson.M{"$eq": "agent_id"}, "filter.rules.value": agentID}
		whiteWithAgent := bson.M{"filter.key": bson.M{"$ne": "agent_id"}}
		whiteCondision = append(whiteCondision, whiteWithAgent)
		whiteCondision = append(whiteCondision, whiteNoAgentId)
		handleQuery = bson.M{AdfnAgentId: agentID, AdfnAlarmStatus: bson.M{"$ne": 0}, AdfnAlarmHitWhite: false}
		whiteQuery = bson.M{"$or": whiteCondision}
		alarmMatchQuery = bson.D{primitive.E{Key: "$match", Value: bson.D{
			primitive.E{Key: "agent_id", Value: agentID},
			primitive.E{Key: "__alarm_status", Value: 0},
			primitive.E{Key: "__hit_wl", Value: false},
		}}}
	} else if clusterID != "" {
		var whiteCondision []bson.M
		whiteNoAgentId := bson.M{"filter.key": bson.M{"$eq": "cluster_id"}, "filter.rules.value": clusterID}
		whiteWithAgent := bson.M{"filter.key": bson.M{"$ne": "cluster_id"}}
		whiteCondision = append(whiteCondision, whiteWithAgent)
		whiteCondision = append(whiteCondision, whiteNoAgentId)
		handleQuery = bson.M{"cluster_id": clusterID, "__alarm_status": bson.M{"$ne": 0}, "__hit_wl": false}
		whiteQuery = bson.M{"$or": whiteCondision}
		alarmMatchQuery = bson.D{primitive.E{Key: "$match", Value: bson.D{
			primitive.E{Key: "cluster_id", Value: clusterID},
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
		primitive.E{Key: AlarmAggregateFieldId, Value: "$SMITH_ALERT_DATA.RULE_INFO.HarmLevel"},
		primitive.E{Key: AlarmAggregateFieldCount, Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
	}}}

	alarmName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return err
	}
	whiteName, err := getWhiteCollectName(alarmType)
	if err != nil {
		return err
	}

	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmName)
	whiteCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(whiteName)

	// level num
	// retCur, aErr := alarmCol.Aggregate(c, mongo.Pipeline{alarmMatchQuery, alarmGroupQuery, alarmProjectQuery})

	retCur, err := alarmCol.Aggregate(ctx, mongo.Pipeline{alarmMatchQuery, alarmGroupQuery})
	if err != nil {
		return err
	}

	defer func() {
		_ = retCur.Close(ctx)
	}()
	var results []bson.M
	err = retCur.All(ctx, &results)
	if err != nil {
		return err
	}

	for _, r := range results {
		sx, sOk := r[AlarmAggregateFieldId].(string)
		ix, iOk := r[AlarmAggregateFieldCount].(int32)
		if !sOk || !iOk {
			continue
		}

		switch sx {
		case AlarmLevelCritical:
			data.CriticalLevelNum = data.CriticalLevelNum + int(ix)
		case AlarmLevelHigh:
			data.HighLevelNum = data.HighLevelNum + int(ix)
		case AlarmLevelMedium:
			data.MediumLevelNum = data.MediumLevelNum + int(ix)
		case AlarmLevelLow:
			data.LowLevelNum = data.LowLevelNum + int(ix)
		}
	}

	// handle num
	handleNum, err := alarmCol.CountDocuments(ctx, handleQuery)
	if err != nil {
		return err
	}

	// white policy num
	whiteNum, err := whiteCol.CountDocuments(ctx, whiteQuery)
	if err != nil {
		return err
	}

	data.Total = data.CriticalLevelNum + data.HighLevelNum + data.MediumLevelNum + data.LowLevelNum
	data.ProcessedNum = int(handleNum)
	data.WhiteListNum = int(whiteNum)

	return nil
}
