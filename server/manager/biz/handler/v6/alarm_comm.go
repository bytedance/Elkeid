package v6

import (
	"errors"
	"strings"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/alarm"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/gin-gonic/gin"
)

func GetAgentContainerInfo(c *gin.Context, data_type string, aid string, pns string, dst *AlarmDataContainerInfo) error {
	dst.ContainerImage = ""
	dst.ContainerName = ""
	queryPns := pns
	var oneInfo = AgentContainerInfo{}

	// pns may be xxx,xxx in killchain, so we split it
	if data_type == "" {
		pnsList := strings.Split(pns, ",")
		if len(pnsList) > 0 {
			queryPns = pnsList[0]
		}
	}

	// query from db
	ctCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintContainerCollection)
	queryJs := bson.M{"agent_id": aid, "pns": queryPns}
	err := ctCol.FindOne(c, queryJs).Decode(&oneInfo)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			ylog.Errorf("GetAgentContainerInfo", "get info error %s", err.Error())
		}

		return err
	}

	dst.ContainerName = oneInfo.Name
	dst.ContainerImage = oneInfo.Image

	return nil
}

func GetAlarmStat(c *gin.Context, alarmType string) {
	var req AgentStatisticsRequest
	var rsp AgentStatisticsResponse

	err := c.BindQuery(&req)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = alarm.QueryAlarmOverview(c, alarmType, req.AgentId, req.ClusterId, &rsp.AlarmOverviewInfo)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, rsp)
}

func QueryRequestUserName(c *gin.Context) (string, error) {
	var retEmptyStr = ""

	user, userOk := c.Get("user")
	if !userOk {
		return retEmptyStr, errors.New("cannot get user info")
	}

	userName, unOk := user.(string)
	if !unOk {
		return retEmptyStr, errors.New("cannot get user name")
	}

	return userName, nil
}

func UpdateAlarmStatusMany(c *gin.Context, alarmType string) {
	var upManyReq alarm.AlarmStatusUpdateManyRequest
	var rsp = make([]AlarmStatusUpdateInfo, 0)
	err := c.BindJSON(&upManyReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// get username
	userName, err := QueryRequestUserName(c)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	err = alarm.UpdateAlarmStatus(alarmType, userName, upManyReq)
	if err != nil {
		CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, rsp)
}

func CompleteAssetHostInfo(raw *alarm.AlarmDbDataInfo, dst *AlarmAssetHost) error {
	if raw.AgentId != nil {
		dst.AgentId = *raw.AgentId
	}

	if raw.HostName != nil {
		dst.HostName = *raw.HostName
	}
	if (raw.InIpv4List != nil) && (*raw.InIpv4List != alarm.AlarmDataMarkEmpty) {
		dst.InnerIPs = append(dst.InnerIPs, strings.Split(*raw.InIpv4List, ",")...)
	}
	if (raw.InIpv6List != nil) && (*raw.InIpv6List != alarm.AlarmDataMarkEmpty) {
		dst.InnerIPs = append(dst.InnerIPs, strings.Split(*raw.InIpv6List, ",")...)
	}
	if (raw.ExIpv4List != nil) && (*raw.ExIpv4List != alarm.AlarmDataMarkEmpty) {
		dst.OuterIPs = append(dst.OuterIPs, strings.Split(*raw.ExIpv4List, ",")...)
	}
	if (raw.ExIpv6List != nil) && (*raw.ExIpv6List != alarm.AlarmDataMarkEmpty) {
		dst.OuterIPs = append(dst.OuterIPs, strings.Split(*raw.ExIpv6List, ",")...)
	}

	return nil
}

func CompleteAssetInfo(c *gin.Context, raw *alarm.AlarmDbDataInfo, dst *AlarmAssetInfo) error {
	var retErr error
	var tmpHostInfo AlarmAssetHost

	// get base info
	if raw.ClusterId != nil {
		dst.Cluster = &raw.AlarmAssetKubeCluter
		return nil
	}

	if raw.AgentId == nil {
		// nothing
		ylog.Errorf("empty agent_id and cluster_id for CompleteAssetInfo", "agent_id is nil")
		return nil
	}

	retErr = CompleteAssetHostInfo(raw, &tmpHostInfo)
	if retErr != nil {
		return retErr
	}

	// get os version
	var tmpHsInfo AlarmDetailDataBaseAgent
	retErr = GetAgentDetail(c, *raw.AgentId, &tmpHsInfo)
	if retErr != nil {
		ylog.Errorf("GetAgentDetail for CompleteAssetInfo error", retErr.Error())
	} else {
		tmpHostInfo.Os = tmpHsInfo.Os
		tmpHostInfo.OsPlatform = tmpHsInfo.OsPlatform
	}

	// get container info
	if raw.ProcessNs != nil {
		var tmpCtInfo AlarmDataContainerInfo
		retErr = GetAgentContainerInfo(c, raw.DataType, *raw.AgentId, *raw.ProcessNs, &tmpCtInfo)
		if retErr != nil {
			ylog.Errorf("GetAgentContainerInfo for CompleteAssetInfo error", retErr.Error())
		} else {
			tmpHostInfo.ContainerImage = &tmpCtInfo.ContainerImage
			tmpHostInfo.ContainerName = &tmpCtInfo.ContainerName
		}
	}

	dst.Host = &tmpHostInfo
	return nil
}

func SplitAlarmExtendInfoProcMatchKeyFromPidTree(agent_id string, pid_tree string) []string {
	retList := make([]string, 0, 50)
	if pid_tree == "" || agent_id == "" {
		return retList
	}

	pidList := strings.Split(pid_tree, "<")
	for _, one := range pidList {
		pidInfo := strings.Split(one, ".")
		if len(pidInfo) != 2 {
			continue
		}

		retList = append(retList, pidInfo[0])
	}

	return retList
}

func SecondaryTreatmentAlarmContent(content *AlarmSummaryContent) {
	if content == nil {
		return
	}

	if content.AlarmNode != nil {
		if (content.AlarmNode.DataType == "6001") ||
			(content.AlarmNode.DataType == "6003") {
			content.AlarmNode.Exec = nil
		}
	}
}

func CompleteAlarmSummaryContent(raw *alarm.AlarmDbDataInfo, dst *AlarmSummaryContent) error {

	procKeyList := make([]string, 0, 50)

	// check kill chain
	if raw.DataType == "" {
		dst.KillChainNodeList = append(dst.KillChainNodeList, raw.KcNodeList...)

		if raw.TopRuleChain != nil {
			dst.KillChainStepList = strings.Split(*raw.TopRuleChain, ",")
		}
	} else {
		// check host info
		if raw.AgentId != nil {
			dst.AlarmNode = &raw.AlarmHidsDataInfo
			if raw.Ppid != nil {
				procKeyList = append(procKeyList, *raw.Ppid)
			}
			if raw.AlarmHidsDataInfo.PidTree != nil {
				tmpProcKeyList := SplitAlarmExtendInfoProcMatchKeyFromPidTree(
					*raw.AgentId, *raw.AlarmHidsDataInfo.PidTree)
				if len(tmpProcKeyList) > 0 {
					procKeyList = append(procKeyList, tmpProcKeyList...)
				}
			}
		}

		// check kube info
		if raw.ClusterId != nil {
			dst.AuditLogAlarm = &raw.AlarmKubeDataInfo
		}
	}

	SecondaryTreatmentAlarmContent(dst)

	return nil
}

func GetAlarmSummaryInfo(c *gin.Context, alarmType string) {
	var rsp AlarmSummaryInfoResponse
	var err error
	alarmID := c.Param("aid")
	if alarmID == "" {
		CreateResponse(c, common.ParamInvalidErrorCode, "alarm_id is empty")
		return
	}

	// query data
	var oneRawAlarm map[string]interface{}
	var oneAlarm = alarm.AlarmDbDataInfo{}
	err = alarm.QueryAlarmParsedData(c, alarmType, alarmID, &oneAlarm)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	err = alarm.QueryAlarmRawData(c, alarmType, alarmID, &oneRawAlarm)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	// convert asset data
	err = CompleteAssetInfo(c, &oneAlarm, &rsp.AssetInfo)
	if err != nil {
		ylog.Errorf("CompleteAssetInfo error", err.Error())
	}

	// convert description
	rsp.AlarmDesc = oneAlarm.AlarmDescription
	// convert contenct
	err = CompleteAlarmSummaryContent(&oneAlarm, &rsp.Content)
	if err != nil {
		ylog.Errorf("CompleteAlarmSummaryContent error", err.Error())
	}

	// copy raw data
	rsp.RawData = oneRawAlarm

	CreateResponse(c, common.SuccessCode, rsp)
}

func ExportAlarmListData(c *gin.Context, alarmType string, headers common.MongoDBDefs, file_name string) {
	var exportReq AlarmExportDataRequest
	err := c.BindJSON(&exportReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	idList, err := alarm.QueryAlarmIDListToBsonA(c, alarmType, exportReq.AlarmIdList, exportReq.Conditions)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	col, err := alarm.QueryAlarmMongodbCollection(alarmType)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	common.ExportFromMongoDB(c, col, bson.M{"_id": bson.M{"$in": idList}}, headers, file_name)
}

func TransAlarmListReqToAlarmFilter(req *AlarmListRequest) *alarm.AlarmQueryFilter {
	if req == nil {
		return nil
	}

	retFilter := &alarm.AlarmQueryFilter{
		Name:          req.Name,
		AgentId:       req.AgentId,
		Hostname:      req.Hostname,
		Ip:            req.Ip,
		EventId:       req.EventId,
		EventName:     req.EventName,
		StatusList:    req.Status,
		TypeList:      req.TypeList,
		StartTime:     req.TimeStart,
		EndTime:       req.TimeEnd,
		LevelList:     req.LevelList,
		EventReason:   req.EventReason,
		FilePath:      req.FilePath,
		FileHash:      req.FileHash,
		ClusterId:     req.ClusterId,
		ClusterRegion: req.ClusterRegion,
		ClusterName:   req.ClusterName,
		TaskID:        req.TaskID,
	}

	return retFilter
}

func GetAlarmFilterByWhite(c *gin.Context, alarmType string) {
	var pageRequest common.PageRequest
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

	searchCont := TransAlarmListReqToAlarmFilter(&listReq)
	if searchCont == nil {
		emptyErr := errors.New("TransAlarmListReqToAlarmFilter return empty")
		CreateResponse(c, common.ParamInvalidErrorCode, emptyErr)
		return
	}

	filterNum, err := alarm.QueryAlarmFilterByWhitelistNum(c, alarmType, searchCont)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	var res AlarmFilterByWhiteData
	res.Total = filterNum
	CreateResponse(c, common.SuccessCode, res)
}

func getAlarmLevelFromAlarmDbData(from alarm.AlarmDbDataInfo) string {
	levelStr := ""

	if from.HidsAlarmLevel != nil {
		levelStr = *from.HidsAlarmLevel
	} else if from.RaspAlarmLevel != nil {
		levelStr = *from.RaspAlarmLevel
	} else if from.KubeAlarmLevel != nil {
		levelStr = *from.KubeAlarmLevel
	} else {
		ylog.Errorf("no alarm level for alarm", "id %s", from.Id)
	}

	return levelStr
}

func getAlarmFieldStringPointerValue(in *string) string {
	if in == nil {
		return ""
	}

	return *in
}

func isNotEmptyStringField(in *string) bool {
	if in == nil {
		return false
	}

	if *in == "" {
		return false
	}

	if *in == "-" {
		return false
	}

	return true
}

func copyAlarmDbDataEventReasonInfo(from alarm.AlarmDbDataInfo, info *[]AlarmAttribution) {
	if from.EventId == nil {
		return
	}

	if info == nil {
		return
	}

	if from.DataType != "" {
		// hids
		if isNotEmptyStringField(from.ReasonIp) {
			tmpIpRea := AlarmAttribution{
				Type:  "IP",
				Value: *from.ReasonIp,
			}
			*info = append(*info, tmpIpRea)
		}

		if isNotEmptyStringField(from.ReasonFile) {
			tmpFileRea := AlarmAttribution{
				Type:  "FILE",
				Value: *from.ReasonFile,
			}

			*info = append(*info, tmpFileRea)
		}

		if isNotEmptyStringField(from.ReasonSid) {
			sidList := strings.Split(*from.ReasonSid, "|")
			tmpSidRea := AlarmAttribution{
				Type:  "SID",
				Value: sidList[0],
			}

			*info = append(*info, tmpSidRea)
		}

		// rasp
		if isNotEmptyStringField(from.StackTraceHash) {
			tmpRhRea := AlarmAttribution{
				Type:  "Hash",
				Value: *from.StackTraceHash,
			}
			*info = append(*info, tmpRhRea)
		}

		// kube
		if isNotEmptyStringField(from.SourceIP) {
			*info = append(*info, AlarmAttribution{
				Type:  "IP",
				Value: *from.SourceIP,
			})
		}

		if isNotEmptyStringField(from.UserAgent) {
			*info = append(*info, AlarmAttribution{
				Type:  "UA",
				Value: *from.UserAgent,
			})
		}

		if isNotEmptyStringField(from.KubeUserName) {
			*info = append(*info, AlarmAttribution{
				Type:  "User",
				Value: *from.KubeUserName,
			})
		}

		if isNotEmptyStringField(from.KubeUserGroup) {
			*info = append(*info, AlarmAttribution{
				Type:  "Groups",
				Value: *from.KubeUserGroup,
			})
		}

		if isNotEmptyStringField(from.ImpUserName) {
			*info = append(*info, AlarmAttribution{
				Type:  "ImpUser",
				Value: *from.ImpUserName,
			})
		}

		if isNotEmptyStringField(from.ImpUserGroup) {
			*info = append(*info, AlarmAttribution{
				Type:  "ImpGroups",
				Value: *from.ImpUserGroup,
			})
		}

	} else { // killchain
		if isNotEmptyStringField(from.ReasonIpList) {
			tmpKcIpRea := AlarmAttribution{
				Type:  "IP",
				Value: *from.ReasonIpList,
			}
			*info = append(*info, tmpKcIpRea)
		}

		if isNotEmptyStringField(from.ReasonFileList) {
			tmpKcFileRea := AlarmAttribution{
				Type:  "FILE",
				Value: *from.ReasonFileList,
			}

			*info = append(*info, tmpKcFileRea)
		}

		if isNotEmptyStringField(from.ReasonSidList) {
			tmpKcSidList := strings.Split(*from.ReasonSidList, ",")
			tmpKcSidValMap := make(map[string]int, 0)
			for _, one := range tmpKcSidList {
				tmpKcSidReaVal := strings.Split(one, "|")
				tmpKcSidValMap[tmpKcSidReaVal[0]] = 1
			}

			for k := range tmpKcSidValMap {
				tmpKcSidRea := AlarmAttribution{
					Type:  "SID",
					Value: k,
				}

				*info = append(*info, tmpKcSidRea)
			}
		}
	}
}

func copyAlarmDbDataIpInfo(from alarm.AlarmDbDataInfo, to *AlarmHostInfo) {
	if isNotEmptyStringField(from.InIpv4List) {
		tmpIp4List := strings.Split(*from.InIpv4List, ",")
		if len(tmpIp4List) > 0 {
			to.InnerIpList = append(to.InnerIpList, tmpIp4List...)
		}
	}

	if isNotEmptyStringField(from.InIpv6List) {
		tmpIp6List := strings.Split(*from.InIpv6List, ",")
		if len(tmpIp6List) > 0 {
			to.InnerIpList = append(to.InnerIpList, tmpIp6List...)
		}
	}

	if isNotEmptyStringField(from.ExIpv4List) {
		tmpOutIp4List := strings.Split(*from.ExIpv4List, ",")
		if len(tmpOutIp4List) > 0 {
			to.OuterIpList = append(to.OuterIpList, tmpOutIp4List...)
		}
	}

	if isNotEmptyStringField(from.ExIpv6List) {
		tmpOutIp6List := strings.Split(*from.ExIpv6List, ",")
		if len(tmpOutIp6List) > 0 {
			to.OuterIpList = append(to.OuterIpList, tmpOutIp6List...)
		}
	}
}

func GetAlarmHostInfoFromAlarm(from alarm.AlarmDbDataInfo) *AlarmHostInfo {
	retInfo := &AlarmHostInfo{
		HostName:    getAlarmFieldStringPointerValue(from.HostName),
		AgentId:     getAlarmFieldStringPointerValue(from.AgentId),
		InnerIpList: make([]string, 0, 5),
		OuterIpList: make([]string, 0, 5),
	}

	// split the ip
	copyAlarmDbDataIpInfo(from, retInfo)

	return retInfo
}

func copyAlarmDbDataToListItem(from alarm.AlarmDbDataInfo) *AlarmListItem {
	oneAlarm := &AlarmListItem{
		AlarmId:     from.Id,
		AgentId:     getAlarmFieldStringPointerValue(from.AgentId),
		HostName:    getAlarmFieldStringPointerValue(from.HostName),
		Status:      from.Status,
		Type:        from.AlertTypeUs,
		Level:       getAlarmLevelFromAlarmDbData(from),
		Name:        getAlarmFieldStringPointerValue(from.RuleName),
		TraceId:     getAlarmFieldStringPointerValue(from.TraceId),
		AlarmTime:   from.InsertTime,
		EventId:     getAlarmFieldStringPointerValue(from.EventId),
		EventName:   getAlarmFieldStringPointerValue(from.EventName),
		DataType:    from.DataType,
		Attribution: make([]AlarmAttribution, 0, 5),
		FilePath:    getAlarmFieldStringPointerValue(from.StaticFile),
		FileHash:    getAlarmFieldStringPointerValue(from.Md5Hash),
		ErrReason:   getAlarmFieldStringPointerValue(from.ErrorReason),
	}

	if from.ClusterId != nil {
		oneAlarm.Cluster = &KubeAlarmClusterInfo{
			ClusterId:   *from.ClusterId,
			ClusterName: getAlarmFieldStringPointerValue(from.ClusterName),
			ClusterArea: getAlarmFieldStringPointerValue(from.ClusterArea),
		}
	} else {
		oneAlarm.Host = GetAlarmHostInfoFromAlarm(from)
	}

	// get the reason
	copyAlarmDbDataEventReasonInfo(from, &oneAlarm.Attribution)

	return oneAlarm
}

func GetAlarmList(c *gin.Context, alarmType string) {
	var pageRequest common.PageRequest
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

	searchCont := TransAlarmListReqToAlarmFilter(&listReq)
	if searchCont == nil {
		CreateResponse(c, common.ParamInvalidErrorCode, "func TransAlarmListReqToAlarmFilter return empty")
		return
	}
	searchFilter := alarm.TransAlarmFilterToBsonM(alarmType, searchCont)

	collection, err := alarm.QueryAlarmMongodbCollection(alarmType)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	pageSearch := common.PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   searchFilter,
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default sort value
		pageSearch.Sorter = bson.M{alarm.AdfnInsertTime: -1}
	}

	var dataResponse []AlarmListItem
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var rawData alarm.AlarmDbDataInfo
			err := cursor.Decode(&rawData)
			if err != nil {
				ylog.Errorf("func GetAlarmList", err.Error())
				return err
			}

			oneAlarm := copyAlarmDbDataToListItem(rawData)
			dataResponse = append(dataResponse, *oneAlarm)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("func GetAlarmList", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}
