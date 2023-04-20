package alarm

import (
	"context"
	"errors"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func getAlarmLevelFieldName(alarmType string) (string, error) {
	var retStr = ""

	switch alarmType {
	case AlarmTypeHids:
		retStr = "harm_level"
	case AlarmTypeRasp:
		retStr = "HarmLevel"
	case AlarmTypeKube:
		retStr = "level"
	default:
		typeErr := errors.New("Unkown alarm type for GetAlarmLevelFieldName")
		return retStr, typeErr
	}

	return retStr, nil
}

func QueryAlarmRawData(ctx context.Context, alarmType string, alarmID string, rawData *map[string]interface{}) error {
	objID, err := primitive.ObjectIDFromHex(alarmID)
	if err != nil {
		return err
	}

	alarmName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return err
	}

	// query data
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmName)
	queryJS := bson.M{"_id": bson.M{"$eq": objID}}
	err = col.FindOne(ctx, queryJS).Decode(rawData)
	if err != nil {
		return err
	}

	return nil
}

func QueryAlarmParsedData(ctx context.Context, alarmType string, alarmID string, data *AlarmDbDataInfo) error {
	objID, err := primitive.ObjectIDFromHex(alarmID)
	if err != nil {
		return err
	}

	alarmName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return err
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmName)
	queryJS := bson.M{"_id": bson.M{"$eq": objID}}
	err = col.FindOne(ctx, queryJS).Decode(data)
	if err != nil {
		return err
	}

	return nil
}

func combineCommAlarmQueryCondision(filter *AlarmQueryFilter, alarmType string, isQueryWhite bool) bson.A {
	searchContent := make(bson.A, 0, 50)

	if filter == nil {
		return searchContent
	}

	if filter.AgentId != "" {
		adFl := bson.M{AdfnAgentId: filter.AgentId}
		searchContent = append(searchContent, adFl)
	}

	if filter.Name != "" {
		enFl := bson.M{AdfnRuleName: bson.M{"$regex": filter.Name}}
		searchContent = append(searchContent, enFl)
	}

	if filter.Hostname != "" {
		hnFl := bson.M{AdfnHostname: bson.M{"$regex": filter.Hostname}}
		searchContent = append(searchContent, hnFl)
	}

	if len(filter.LevelList) > 0 {
		lvFl := bson.M{AdfnLevel: bson.M{
			"$in": filter.LevelList,
		}}
		searchContent = append(searchContent, lvFl)
	}

	if len(filter.StatusList) > 0 {
		stFl := bson.M{AdfnAlarmStatus: bson.M{
			"$in": filter.StatusList,
		}}
		searchContent = append(searchContent, stFl)
	}

	if filter.StartTime > 0 {
		etFl := bson.M{AdfnInsertTime: bson.M{
			"$gte": filter.StartTime,
		}}
		searchContent = append(searchContent, etFl)
	}

	if filter.EndTime > 0 {
		etFl := bson.M{AdfnInsertTime: bson.M{
			"$lte": filter.EndTime,
		}}
		searchContent = append(searchContent, etFl)
	}

	if len(filter.TypeList) > 0 {
		tgFl := bson.M{AdfnAlertType: bson.M{
			"$in": filter.TypeList,
		}}
		searchContent = append(searchContent, tgFl)
	}

	if filter.Ip != "" {
		ipFl := bson.M{"$or": bson.A{
			bson.M{AdfnHostInIpv4: bson.M{"$regex": filter.Ip}},
			bson.M{AdfnHostOutIpv4: bson.M{"$regex": filter.Ip}},
			bson.M{AdfnHostInIpv6: bson.M{"$regex": filter.Ip}},
			bson.M{AdfnHostOutIpv6: bson.M{"$regex": filter.Ip}},
		}}

		searchContent = append(searchContent, ipFl)
	}

	if filter.EventId != "" {
		eiFl := bson.M{AdfnEventId: filter.EventId}
		searchContent = append(searchContent, eiFl)
	}

	if filter.EventName != "" {
		etFl := bson.M{AdfnEventName: bson.M{"$regex": filter.EventName}}
		searchContent = append(searchContent, etFl)
	}

	if filter.ClusterId != "" {
		searchContent = append(searchContent, bson.M{AdfnClusterId: filter.ClusterId})
	}

	if filter.ClusterName != "" {
		searchContent = append(searchContent, bson.M{AdfnClusterName: bson.M{"$regex": filter.ClusterName}})
	}

	if filter.ClusterRegion != "" {
		searchContent = append(searchContent, bson.M{AdfnClucsterArea: bson.M{"$regex": filter.ClusterRegion}})
	}

	if filter.EventReason != "" {
		erFl := bson.M{}

		switch alarmType {
		case AlarmTypeHids:
			erFl = bson.M{"$or": bson.A{
				bson.M{AdfnReasonFile: bson.M{"$regex": filter.EventReason}},
				bson.M{AdfnReasonIp: bson.M{"$regex": filter.EventReason}},
				bson.M{AdfnReasonSid: bson.M{"$regex": filter.EventReason}},
				bson.M{AdfnKcReasonFile: bson.M{"$regex": filter.EventReason}},
				bson.M{AdfnKcReasonIp: bson.M{"$regex": filter.EventReason}},
				bson.M{AdfnReasonSid: bson.M{"$regex": filter.EventReason}},
			}}
		case AlarmTypeRasp:
			erFl = bson.M{"$regex": filter.EventReason}
		case AlarmTypeKube:
			erFl = bson.M{
				"$or": bson.A{
					bson.M{AdfnReasonKubeSrcIp: bson.M{"$regex": filter.EventReason}},
					bson.M{AdfnReasonKubeUA: bson.M{"$regex": filter.EventReason}},
					bson.M{AdfnReasonKubeUserName: bson.M{"$regex": filter.EventReason}},
					bson.M{AdfnReasonKubeUserGroup: bson.M{"$regex": filter.EventReason}},
					bson.M{AdfnReasonKubeIUserName: bson.M{"$regex": filter.EventReason}},
					bson.M{AdfnReasonKubeIUserGroup: bson.M{"$regex": filter.EventReason}},
				},
			}
		default:
			break
		}

		searchContent = append(searchContent, erFl)
	}

	if filter.FilePath != "" {
		fpFl := bson.M{AdfnStaticFilePath: bson.M{"$regex": filter.FilePath}}
		searchContent = append(searchContent, fpFl)
	}

	if filter.FileHash != "" {
		fhFl := bson.M{AdfnStaticFileHash: bson.M{"$regex": filter.FileHash}}
		searchContent = append(searchContent, fhFl)
	}

	if filter.TaskID != "" {
		tokenList := atask.GetSubTaskTokenList(context.TODO(), filter.TaskID)
		if len(tokenList) > 0 {
			tkFl := bson.M{AdfnTaskToken: bson.M{"$in": tokenList}}
			searchContent = append(searchContent, tkFl)
		}
	}

	wtFl := bson.M{AdfnAlarmHitWhite: isQueryWhite}
	searchContent = append(searchContent, wtFl)

	return searchContent
}

func QueryAlarmFilterByWhitelistNum(ctx context.Context, alarmType string, filter *AlarmQueryFilter) (int64, error) {
	var retNum int64 = 0
	if filter == nil {
		return retNum, nil
	}

	colName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return retNum, err
	}

	searchFilterContent := combineCommAlarmQueryCondision(filter, alarmType, true)
	searchFilter := bson.M{"$and": searchFilterContent}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(colName)
	num, err := collection.CountDocuments(ctx, searchFilter)
	if err != nil {
		return retNum, err
	}

	return num, nil
}

func QueryAlarmMongodbCollection(alarmType string) (*mongo.Collection, error) {
	colName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return nil, err
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(colName)

	return col, nil
}

func QueryAlarmIDListToBsonA(ctx context.Context, alarmType string, alarmIDList *[]string, filter *AlarmQueryFilter) (bson.A, error) {
	var tmpList []string
	idList := bson.A{}
	colName, err := getAlarmCollectName(alarmType)
	if err != nil {
		return idList, err
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(colName)

	// query alarm id
	if alarmIDList != nil {
		tmpList = append(tmpList, *alarmIDList...)
	} else if filter != nil {
		alarmManyQueryCont := combineCommAlarmQueryCondision(filter, alarmType, false)
		alarmManyQuery := bson.M{
			"$and": alarmManyQueryCont,
		}
		alarmManyCur, err := col.Find(ctx, alarmManyQuery)
		if err != nil {
			return idList, err
		}

		var manayRes []AlarmDbDataInfo
		err = alarmManyCur.All(ctx, &manayRes)
		if err != nil {
			return idList, err
		}

		for _, one := range manayRes {
			tmpList = append(tmpList, one.Id)
		}
	}

	for _, one := range tmpList {
		if oid, err := primitive.ObjectIDFromHex(one); err == nil {
			idList = append(idList, oid)
		}
	}

	return idList, nil
}

func TransAlarmFilterToBsonM(alarmType string, filter *AlarmQueryFilter) bson.M {
	var retBson bson.M
	if filter == nil {
		return retBson
	}

	searchFilterContent := combineCommAlarmQueryCondision(filter, alarmType, false)
	retBson = bson.M{"$and": searchFilterContent}

	return retBson
}

func QueryAlarmDayStat(ctx context.Context, nowTime int64, alarmType string, dayNum int) (*AlarmOverviewStat, map[int64]AlarmOverviewDayTrend, error) {
	var retStat = AlarmOverviewStat{
		CriticalNum: 0,
		HighNum:     0,
		MediumNum:   0,
		LowNum:      0,
		TotalNum:    0,
	}

	var retTrend = make(map[int64]AlarmOverviewDayTrend)

	queryStartTime := GetAlarmDayStatDayTimeIndex(nowTime, 1-dayNum)
	queryEndTime := GetAlarmDayStatDayTimeIndex(nowTime, 1)

	alarmColName, cErr := getAlarmCollectName(alarmType)
	if cErr != nil {
		return &retStat, retTrend, cErr
	}

	statColName, sErr := getAlarmStatCollectionName(alarmType)
	if sErr != nil {
		return &retStat, retTrend, sErr
	}

	levelFieldName, lErr := getAlarmLevelFieldName(alarmType)
	if lErr != nil {
		return &retStat, retTrend, lErr
	}

	fieldKey := "$" + levelFieldName

	// unhandle info
	filterJs := bson.D{primitive.E{Key: "$match", Value: bson.D{
		primitive.E{Key: "__alarm_status", Value: 0},
		primitive.E{Key: "__hit_wl", Value: false},
	}}}
	groupJs := bson.D{primitive.E{Key: "$group", Value: bson.D{
		primitive.E{Key: "_id", Value: fieldKey},
		primitive.E{Key: "count", Value: bson.D{
			primitive.E{Key: "$sum", Value: 1},
		}},
	}}}
	projectJs := bson.D{primitive.E{Key: "$project", Value: bson.D{
		primitive.E{Key: "level", Value: "$_id"},
		primitive.E{Key: "count", Value: 1},
	}}}
	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(alarmColName)
	pipeline := mongo.Pipeline{
		filterJs,
		groupJs,
		projectJs,
	}

	opts := options.Aggregate().SetMaxTime(15 * time.Second)
	alarmCur, aErr := alarmCol.Aggregate(ctx, pipeline, opts)
	if aErr != nil {
		return &retStat, retTrend, aErr
	}

	var unhandleStatList []AlarmUnhandleStatusAggresOut
	aErr = alarmCur.All(ctx, &unhandleStatList)
	if aErr != nil {
		_ = alarmCur.Close(ctx)
		return &retStat, retTrend, aErr
	}
	for _, one := range unhandleStatList {
		switch one.Level {
		case AlarmLevelCritical:
			retStat.CriticalNum = retStat.CriticalNum + one.Count
			break
		case AlarmLevelHigh:
			retStat.HighNum = retStat.HighNum + one.Count
			break
		case AlarmLevelMedium:
			retStat.MediumNum = retStat.MediumNum + one.Count
			break
		case AlarmLevelLow:
			retStat.LowNum = retStat.LowNum + one.Count
			break
		default:
			continue
		}
		retStat.TotalNum = retStat.TotalNum + one.Count
	}

	_ = alarmCur.Close(ctx)

	// day trend
	statCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(statColName)
	queryJs := bson.M{"daytime": bson.M{"$gte": queryStartTime, "$lt": queryEndTime}}
	statCur, qErr := statCol.Find(ctx, queryJs)
	if qErr != nil {
		return &retStat, retTrend, qErr
	}

	var dayStats []AlarmDailyStatInfo
	qErr = statCur.All(ctx, &dayStats)
	if qErr != nil {
		_ = statCur.Close(ctx)
		return &retStat, retTrend, qErr
	}
	for _, two := range dayStats {
		tmpTrend := AlarmOverviewDayTrend{
			DayTime:          two.DayTime,
			UnhandleAlarmNum: two.UnhandleNum,
		}
		retTrend[two.DayTime] = tmpTrend
	}

	_ = statCur.Close(ctx)

	return &retStat, retTrend, nil
}
