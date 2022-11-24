package v6

import (
	"fmt"
	"time"

	"github.com/rs/xid"

	"github.com/bytedance/Elkeid/server/manager/internal/alarm"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/gin-gonic/gin"
)

// ############################### Data Struct ###############################
//
//goland:noinspection GoUnusedGlobalVariable
var AlarmTypeCnToEn = map[string]string{
	"暴力破解": "bruteforce",
	"提权攻击": "privilege_escalation",
	"后门驻留": "persistent",
	"变形木马": "evasion",
	"恶意破坏": "purpose",
	"静态检测": "static_scan",
	"杀伤链":  "killchain",
}

//goland:noinspection GoUnusedGlobalVariable
var AlarmTypeEnToCn = map[string]string{
	"bruteforce":                 "暴力破解",
	"privilege_escalation":       "提权攻击",
	"persistent":                 "后门驻留",
	"evasion":                    "变形木马",
	"purpose":                    "恶意破坏",
	"static_scan":                "静态检测",
	"killchain":                  "杀伤链",
	"initial_access":             "试探入侵",
	"execution":                  "代码执行",
	"credential_access":          "账密盗用",
	"discovery":                  "资产探测",
	"collection":                 "信息收集",
	"lateral_movement":           "横向移动",
	"command_control":            "隐蔽隧道",
	"exfiltration":               "信息外渗",
	"custom":                     "用户自定义",
	"Code Execution":             "代码执行",
	"Abnormal File Read/Write":   "异常文件读写",
	"Abnormal Network Connect":   "异常网络",
	"Path Traversal":             "目录遍历",
	"Abnormal Behavior Sequence": "异常行为序列",
	"Abnormal Runtime Behavior":  "异常行为",
	"SQL Injection":              "SQL注入",
}

// ############################### Variable ###############################
const (
	ALARM_STAT_AGGREGATE_GROUP_ID    string = "_id"
	ALARM_STAT_AGGREGATE_GROUP_COUNT string = "count"
)

var VirusDetectionDataTypeList = []string{"6000", "6001", "6002", "6003", "6005", "6010"}

// ############################### Function ###############################
func GetAlarmListForHids(c *gin.Context) {
	GetAlarmList(c, alarm.AlarmTypeHids)
}

func GetAgentDetail(c *gin.Context, aid string, dst *AlarmDetailDataBaseAgent) error {
	var oneHb = AgentHbInfo{}
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
	dst.HostName = oneHb.HostName
	dst.Os = fmt.Sprintf("%s %s", oneHb.PlatformFamily, oneHb.PlatformVersion)
	dst.OsPlatform = oneHb.Platform
	dst.InnerIPs = make([]string, len(oneHb.InnerIPv4))
	dst.OuterIPs = make([]string, len(oneHb.OuterIPv4))
	copy(dst.InnerIPs, oneHb.InnerIPv4)
	copy(dst.OuterIPs, oneHb.OuterIPv4)

	return nil
}

func GetAlarmStatForHids(c *gin.Context) {
	GetAlarmStat(c, alarm.AlarmTypeHids)
}

func UpdateAlarmStatusManyForHids(c *gin.Context) {
	UpdateAlarmStatusMany(c, alarm.AlarmTypeHids)
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
	newAlarm["__checker"] = ""
	newAlarm["__hit_wl"] = false
	newAlarm["__handler_user"] = ""

	// check type
	isVirusDetectionData := false

	dataTypeInter, dOk := newAlarm["data_type"]
	if dOk {
		dataType, sOk := dataTypeInter.(string)
		if sOk {
			for _, one := range VirusDetectionDataTypeList {
				if dataType == one {
					isVirusDetectionData = true
					break
				}
			}
		}
	}

	alarmID := xid.New().String()
	newAlarm["alarm_id"] = alarmID

	if isVirusDetectionData {
		dbtask.VirusDetectionAsyncWrite(newAlarm)
	} else {
		// write to db
		dbtask.HubAlarmAsyncWrite(newAlarm)
	}

	// send response
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func GetAlarmFilterByWhiteForHids(c *gin.Context) {
	GetAlarmFilterByWhite(c, alarm.AlarmTypeHids)
}

func ExportAlarmListDataForHids(c *gin.Context) {
	exportFileName := "Exported-HostAlarm"

	var exportHeaders = common.MongoDBDefs{
		{Key: "rule_name", Header: "rule_name"},
		{Key: "alert_type_us", Header: "type"},
		{Key: "harm_level", Header: "level"},
		{Key: "__alarm_status", Header: "status"},
		{Key: "hostname", Header: "hostname"},
		{Key: "event_name", Header: "event_name"},
		{Key: "__insert_time", Header: "alarm_time"},
	}

	ExportAlarmListData(c, alarm.AlarmTypeHids, exportHeaders, exportFileName)
}

func GetAlarmSummaryInfoForHids(c *gin.Context) {
	GetAlarmSummaryInfo(c, alarm.AlarmTypeHids)
}
