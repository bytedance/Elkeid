package v6

import (
	"context"
	"time"

	"github.com/rs/xid"

	"github.com/bytedance/Elkeid/server/manager/internal/alarm"
	"github.com/bytedance/Elkeid/server/manager/internal/alarm_whitelist"
	"github.com/bytedance/Elkeid/server/manager/internal/kube"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"

	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
)

const KubeDefFilterItemNum int = 50

// ############################### Function ###############################

// for test
func KubeInnerTestNewCert(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "name is empty")
		return
	}
	key, cert, err := kube.CreateCert(name, 365*24*time.Hour)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, bson.M{"key": string(key), "cert": string(cert), "cluster_id": name})
}

func KubeInnerClusterList(c *gin.Context) {
	idList := make([]string, 0)
	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	cursor, err := clusterCol.Find(c, bson.M{})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err)
		return
	}
	for cursor.Next(c) {
		clusterId, ok := cursor.Current.Lookup("cluster_id").StringValueOK()
		if ok {
			idList = append(idList, clusterId)
		}
	}
	common.CreateResponse(c, common.SuccessCode, idList)
}

func KubeAddOneAlarm(c *gin.Context) {
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

	//新增到溯源
	/*
		traceID := trace.TS.CreateTraceID()
		newAlarm["trace_id"] = traceID
		//newAlarm 后续都是只读，不能再更改
		trace.TS.NewTraceWithID(newAlarm, traceID)
	*/

	// write to db
	dbtask.KubeAlarmAsyncWrite(newAlarm)

	// send response
	common.CreateResponse(c, common.SuccessCode, "ok")
}

// raw data

// filter
func KubeCombineAlarmFilter(filter *KubeAlarmFilter, isQueryWhite bool) bson.A {
	retFilter := make(bson.A, 0, KubeDefFilterItemNum)

	if filter.ClusterId != "" {
		retFilter = append(retFilter, bson.M{"cluster_id": filter.ClusterId})
	}

	if filter.ClusterName != "" {
		retFilter = append(retFilter, bson.M{"cluster": bson.M{"$regex": filter.ClusterName}})
	}

	if filter.ClusterRegion != "" {
		retFilter = append(retFilter, bson.M{"cluster_area": bson.M{"$regex": filter.ClusterRegion}})
	}

	if filter.Name != "" {
		retFilter = append(retFilter, bson.M{"rule_name": bson.M{"$regex": filter.Name}})
	}

	if filter.StartTime > 0 {
		retFilter = append(retFilter, bson.M{"__insert_time": bson.M{"$gte": filter.StartTime}})
	}

	if filter.EndTime > 0 {
		retFilter = append(retFilter, bson.M{"__insert_time": bson.M{"$lte": filter.EndTime}})
	}

	if filter.EventId != "" {
		retFilter = append(retFilter, bson.M{"event_id": filter.EventId})
	}

	if filter.EventName != "" {
		retFilter = append(retFilter, bson.M{"event_name": bson.M{"$regex": filter.EventName}})
	}

	if filter.EventReason != "" {
		retFilter = append(retFilter, bson.M{
			"$or": bson.A{
				bson.M{"source_ip": bson.M{"$regex": filter.EventReason}},
				bson.M{"user_agent": bson.M{"$regex": filter.EventReason}},
				bson.M{"user_name": bson.M{"$regex": filter.EventReason}},
				bson.M{"user_groups": bson.M{"$regex": filter.EventReason}},
				bson.M{"impersonated_user_name": bson.M{"$regex": filter.EventReason}},
				bson.M{"impersonated_user_groups": bson.M{"$regex": filter.EventReason}},
			},
		})
	}

	if len(filter.LevelList) > 0 {
		retFilter = append(retFilter, bson.M{"level": bson.M{"$in": filter.LevelList}})
	}

	if len(filter.StatusList) > 0 {
		retFilter = append(retFilter, bson.M{"__alarm_status": bson.M{"$in": filter.StatusList}})
	}

	if len(filter.TypeList) > 0 {
		retFilter = append(retFilter, bson.M{"alert_type_us": bson.M{"$in": filter.TypeList}})
	}

	// filter white
	// retFilter = append(retFilter, bson.M{"__checked": true, "__hit_wl": false})
	retFilter = append(retFilter, bson.M{"__hit_wl": isQueryWhite})
	return retFilter
}

func (t *KubeAuditLogListFilterComm) getAuditLogCommFilter(filter *bson.A) {
	if t.ClusterId != "" {
		*filter = append(*filter, bson.M{"cluster_id": t.ClusterId})
	}

	if t.ClusterName != "" {
		*filter = append(*filter, bson.M{"cluster": bson.M{"$regex": t.ClusterName}})
	}

	if t.Region != "" {
		*filter = append(*filter, bson.M{"cluster_area": bson.M{"$regex": t.Region}})
	}

	if len(t.RiskLevelList) > 0 {
		*filter = append(*filter, bson.M{"level": bson.M{"$in": t.RiskLevelList}})
	}

	if len(t.RiskNameList) > 0 {
		*filter = append(*filter, bson.M{"rule_name_us": bson.M{"$in": t.RiskNameList}})
	}

	if t.User != "" {
		*filter = append(*filter, bson.M{"real_user_name": bson.M{"$regex": t.User}})
	}

	if t.UserGroup != "" {
		*filter = append(*filter, bson.M{"real_user_groups": bson.M{"$regex": t.UserGroup}})
	}

	if t.UserAgent != "" {
		*filter = append(*filter, bson.M{"user_agent": bson.M{"$regex": t.UserAgent}})
	}

	if t.SourceIp != "" {
		*filter = append(*filter, bson.M{"source_ip": bson.M{"$regex": t.SourceIp}})
	}

	if t.SourcePsm != "" {
		*filter = append(*filter, bson.M{"source_ip_asset": bson.M{"$regex": t.SourcePsm}})
	}

	if t.ResKind != "" {
		*filter = append(*filter, bson.M{"resource_kind": bson.M{"$regex": t.ResKind}})
	}

	if t.ResName != "" {
		*filter = append(*filter, bson.M{"resource_name": bson.M{"$regex": t.ResName}})
	}

	if t.ResNamespace != "" {
		*filter = append(*filter, bson.M{"resource_namespace": bson.M{"$regex": t.ResNamespace}})
	}

	if t.CreateTimeStart != 0 {
		*filter = append(*filter, bson.M{"__insert_time": bson.M{"$gte": t.CreateTimeStart}})
	}

	if t.CreateTimeEnd != 0 {
		*filter = append(*filter, bson.M{"__insert_time": bson.M{"$lte": t.CreateTimeEnd}})
	}
}

func kubeBuildAlarmListItemFromRaw(raw KubeAlarmSimpleInfoItem) *KubeAlarmListResponseItem {

	atbList := make([]AlarmAttribution, 0)

	return &KubeAlarmListResponseItem{
		AlarmId:     raw.AlarmId,
		ClusterId:   raw.ClusterId,
		Status:      raw.Status,
		Level:       raw.Level,
		Name:        raw.RuleName,
		Type:        raw.AlertType,
		AlarmTime:   raw.CreateTime,
		TraceId:     "notrace",
		DataType:    "",
		Attribution: atbList,
		Cluster: KubeAlarmClusterInfo{
			ClusterId:      raw.ClusterId,
			ClusterName:    raw.ClusterName,
			ClusterArea:    raw.ClusterArea,
			RuleTypeFirst:  "",
			RuleTypeSecond: "",
		},
	}
}

// list
func KubeListAlarm(c *gin.Context) {
	var alReq KubeAlarmListRequest
	var pageRequest common.PageRequest

	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = c.BindJSON(&alReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	confFilter := &KubeAlarmFilter{
		Name:          alReq.Name,
		ClusterId:     alReq.ClusterId,
		ClusterRegion: alReq.ClusterRegion,
		ClusterName:   alReq.ClusterName,
		StatusList:    alReq.Status,
		TypeList:      alReq.TypeList,
		LevelList:     alReq.LevelList,
		StartTime:     alReq.StartTime,
		EndTime:       alReq.EndTime,
		EventName:     alReq.EventName,
		EventId:       alReq.EventId,
		EventReason:   alReq.EventReason,
	}

	var dataResponse = make([]KubeAlarmListResponseItem, 0, pageRequest.PageSize)
	searchFilterContent := KubeCombineAlarmFilter(confFilter, false)
	searchFilter := bson.M{}
	if len(searchFilterContent) > 0 {
		searchFilter = bson.M{"$and": searchFilterContent}
	}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeAlarmCollectionV1)
	pageSearch := common.PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   searchFilter,
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default sort value
		pageSearch.Sorter = bson.M{"__insert_time": -1}
	}

	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var rawData KubeAlarmSimpleInfoItem
			tmpErr := cursor.Decode(&rawData)
			if err != nil {
				ylog.Errorf("KubeListAbnormalBehavior", tmpErr.Error())
				return err
			}

			// trans
			tmpItem := kubeBuildAlarmListItemFromRaw(rawData)
			dataResponse = append(dataResponse, *tmpItem)
			return nil
		},
	)

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

func (t *KubeThreatAnalysisListBaseItem) KubeTransThreatRawBaseDataToRspBaseData() {
	if t.ResKind != nil {
		t.ResInfo.Kind = *t.ResKind
		t.ResKind = nil
	}

	if t.ResNamespace != nil {
		t.ResInfo.Namespace = *t.ResNamespace
		t.ResNamespace = nil
	}

	if t.ResName != nil {
		t.ResInfo.Name = *t.ResName
		t.ResName = nil
	}

	if t.SourceIP != nil {
		t.Source.IP = *t.SourceIP
		t.SourceIP = nil
	}

	if t.SourceAsset != nil {
		t.Source.PSM = *t.SourceAsset
		t.SourceAsset = nil
	}
}

// ********************************* Summary *********************************

// ********************************* Statistics *********************************
func GetAlarmStatForKube(c *gin.Context) {
	GetAlarmStat(c, alarm.AlarmTypeKube)
}

// ********************************* status update *********************************
func UpdateAlarmStatusManyForKube(c *gin.Context) {
	UpdateAlarmStatusMany(c, alarm.AlarmTypeKube)
}

func GetAlarmFilterByWhiteForKube(c *gin.Context) {
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	var listReq KubeAlarmListRequest
	err = c.BindJSON(&listReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	searchCont := &KubeAlarmFilter{
		Name:          listReq.Name,
		EventId:       listReq.EventId,
		EventName:     listReq.EventName,
		ClusterId:     listReq.ClusterId,
		ClusterName:   listReq.ClusterName,
		ClusterRegion: listReq.ClusterRegion,
		StatusList:    listReq.Status,
		TypeList:      listReq.TypeList,
		StartTime:     listReq.StartTime,
		EndTime:       listReq.EndTime,
		LevelList:     listReq.LevelList,
		EventReason:   listReq.EventReason,
	}
	searchFilterContent := KubeCombineAlarmFilter(searchCont, true)
	searchFilter := bson.M{"$and": searchFilterContent}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeAlarmCollectionV1)
	num, err := collection.CountDocuments(c, searchFilter)
	if err != nil {
		ylog.Errorf("GetAlarmFilterByWhite", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	}

	var res AlarmFilterByWhiteData
	res.Total = num
	CreateResponse(c, common.SuccessCode, res)
}

// ********************************* export *********************************
func ExportKubeAlarmListData(c *gin.Context) {
	var exportReq KubeAlarmExportDataRequest
	var agList []string
	err := c.BindJSON(&exportReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeAlarmCollectionV1)

	// query alarm id
	if exportReq.AlarmIdList != nil {
		agList = append(agList, *exportReq.AlarmIdList...)
	} else if exportReq.Conditions != nil {
		alarmManyQueryCont := KubeCombineAlarmFilter(exportReq.Conditions, false)
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
		{Key: "level", Header: "level"},
		{Key: "__alarm_status", Header: "status"},
		{Key: "cluster", Header: "cluster"},
		{Key: "event_name", Header: "event_name"},
		{Key: "__insert_time", Header: "alarm_time"},
	}

	idList := bson.A{}
	for _, one := range agList {
		if oid, err := primitive.ObjectIDFromHex(one); err == nil {
			idList = append(idList, oid)
		}
	}

	filename := "Exported-KubeAlarm"
	common.ExportFromMongoDB(c, col, bson.M{"_id": bson.M{"$in": idList}}, alarmDetailDataHeaders, filename)
}

// ********************************* whitelist *********************************
func MultiDelWhiteListForKube(c *gin.Context) {
	WhiteListDelMulti(c, alarm_whitelist.WhitelistTypeKube)
}

func GetWhiteListWithCombineForKube(c *gin.Context) {
	GetWhiteListWithCombine(c, alarm_whitelist.WhitelistTypeKube)
}

func MultiAddWhiteListWithCombineForKube(c *gin.Context) {
	WhiteListAddMultiWithCombine(c, alarm_whitelist.WhitelistTypeKube)
}

// ********************************* cluster info *********************************
func KubeQueryClusterInfo(ctx context.Context, cluster_id string) *KubeClusterBaseInfo {

	var retInfo = KubeClusterBaseInfo{
		ClusterId:   "",
		ClusterName: "",
		ClusterArea: "",
	}

	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	err := kubeConfCol.FindOne(ctx, bson.M{"cluster_id": cluster_id}).Decode(&retInfo)
	if err != nil {
		ylog.Errorf("KubeQueryClusterInfo", "error %s", err)
	}

	return &retInfo
}

func GetAlarmSummaryInfoForKube(c *gin.Context) {
	GetAlarmSummaryInfo(c, alarm.AlarmTypeKube)
}

func WhiteListUpdateOneForKube(c *gin.Context) {
	WhiteListUpdateOne(c, alarm_whitelist.WhitelistTypeKube)
}
