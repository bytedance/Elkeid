package v6

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/outputer"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// ********************************* const value *********************************

// ********************************* struct *********************************
type NoticeConnectTestResult struct {
	Status int    `json:"status" bson:"status"`
	ErrMsg string `json:"err_msg" bson:"err_msg"`
}

type NoticeWriteRequestComm struct {
	Type      string                   `json:"notice_type" bson:"notice_type"`
	LevelList []string                 `json:"notice_level_list" bson:"notice_level_list"`
	MsgType   string                   `json:"notice_config_type" bson:"notice_config_type"`
	MsgConfig outputer.NoticeMsgConfig `json:"notice_config" bson:"notice_config"`
	TestOnly  bool                     `json:"test_only,omitempty" bson:"test_only,omitempty"`
}

type NoticeAddOneRequest struct {
	NoticeWriteRequestComm `json:",inline" bson:",inline"`
}

type NoticeDelOneRequest struct {
	NoticeId string `json:"notice_id" bson:"notice_id"`
}

type NoticeModifyOneRequest struct {
	NoticeId               string `json:"notice_id" bson:"notice_id"`
	NoticeWriteRequestComm `json:",inline" bson:",inline"`
}

type NoticeOneChangeRunConfigRequest struct {
	NoticeId  string   `json:"notice_id"`
	LevelList []string `json:"notice_level_list,omitempty"`
	Opt       *int     `json:"opt,omitempty"`
}

type NoticeCommResponse struct {
	NoticeId   *string                  `json:"notice_id,omitempty" bson:"notice_id,omitempty"`
	TestResult *NoticeConnectTestResult `json:"test_result,omitempty" bson:"test_result,omitempty"`
}

// ********************************* function *********************************
func CheckNoticeMsgConfig(msg_type string, notice_type string, config *outputer.NoticeMsgConfig, needTest bool) error {
	var errMsg = ""
	var alarmType = ""

	switch notice_type {
	case outputer.DataModelHidsAlarm:
		alarmType = outputer.HubPluginMsgTypeAlarm
	case outputer.DataModelRaspAlarm:
		alarmType = outputer.HubPluginMsgTypeAlarm
	case outputer.DataModelKubeAlarm:
		alarmType = outputer.HubPluginMsgTypeAlarm
	case outputer.DataModelVirusAlarm:
		alarmType = outputer.HubPluginMsgTypeAlarm
	case outputer.DataModelAuthorizationExpire:
		alarmType = outputer.HubPluginMsgTypeReminder
	default:
		return errors.New("wrong notice type for CheckNoticeMsgConfig")
	}

	switch msg_type {
	case outputer.ConfigTypeFeishu:
		return TestNoticePushMsgToFeishuByHub(config.FeishuConfig, alarmType, needTest)
	case outputer.ConfigTypeDingding:
		return TestNoticePushMsgToDingdingByHub(config.DingdingConfig, alarmType, needTest)
	case outputer.ConfigTypeSyslog:
		return TestNoticePushMsgToSysLog(config.Syslog, needTest)
	case outputer.ConfigTypeEWechat:
		return TestNoticePushMsgToEWechatByHub(config.EWechat, alarmType, needTest)
	case outputer.ConfigTypeEmail:
		return TestNoticePushMsgToEmailByHub(config.Email, alarmType, needTest)
	case outputer.ConfigTypeEs:
		return TestNoticePushMsgToEs(config.ES, needTest)
	case outputer.ConfigTypeKafka:
		return TestNoticePushMsgToKafka(config.Kafka, needTest)
	case outputer.ConfigTypeCustom:
		return TestNoticePushMsgToCustomByHub(config.Custom, alarmType, needTest)
	default:
		errMsg = fmt.Sprintf("unkown notice message type %s", msg_type)
		return errors.New(errMsg)
	}
}

func GetNoticeDesc(noticeType string) string {
	var retStr = ""

	switch noticeType {
	case outputer.DataModelHidsAlarm:
		retStr = "发生了安全告警需处理则发送通知"
	case outputer.DataModelRaspAlarm:
		retStr = "发生了安全告警需处理则发送通知"
	case outputer.DataModelKubeAlarm:
		retStr = "发生了安全告警需处理则发送通知"
	case outputer.DataModelVirusAlarm:
		retStr = "发生了安全告警需处理则发送通知"
	case outputer.DataModelAuthorizationExpire:
		retStr = "提前30天提醒授权即将到期状态、授权过期提醒"
	}

	return retStr
}

func GetNoticeAbstract(msgType string, config *outputer.NoticeMsgConfig) string {
	var retStr = ""

	switch msgType {
	case outputer.ConfigTypeFeishu:
		if config.FeishuConfig.Remarks != "" {
			retStr = config.FeishuConfig.Remarks
		} else {
			retStr = config.FeishuConfig.WebHookUrl
		}
	case outputer.ConfigTypeDingding:
		if config.DingdingConfig.Remarks != "" {
			retStr = config.DingdingConfig.Remarks
		} else {
			retStr = config.DingdingConfig.WebHookUrl
		}
	case outputer.ConfigTypeSyslog:
		retStr = config.Syslog.SyslogServer
	case outputer.ConfigTypeEWechat:
		if config.EWechat.Remarks != "" {
			retStr = config.EWechat.Remarks
		} else {
			retStr = config.EWechat.WebHookUrl
		}
	case outputer.ConfigTypeEmail:
		retStr = strings.Join(config.Email.ToEmail, ";")
	case outputer.ConfigTypeEs:
		retStr = strings.Join(config.ES.ESHost, ",")
	case outputer.ConfigTypeKafka:
		retStr = config.Kafka.KafkaBootstrapServers
	case outputer.ConfigTypeCustom:
		retStr = config.Custom.PluginName
	}

	return retStr
}

func GetNoticeList(c *gin.Context) {
	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	searchFilter := bson.M{}
	// db opt
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	pageSearch := common.PageSearch{Page: pageRequest.Page,
		PageSize: pageRequest.PageSize,
		Filter:   searchFilter,
		Sorter:   nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	} else {
		// default sort value
		pageSearch.Sorter = bson.M{"_id": -1}
	}

	var dataResponse []outputer.NoticeRunConfig
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var rawData outputer.NoticeConfigDbDataFormat
			err := cursor.Decode(&rawData)
			if err != nil {
				ylog.Errorf("GetNoticeList", err.Error())
				return err
			}

			oneData := rawData.NoticeRunConfig
			oneData.NoticeId = &rawData.ID
			dataResponse = append(dataResponse, oneData)
			return nil
		},
	)

	if err != nil {
		ylog.Errorf("GetNoticeList", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

func AddOneNoticeConfig(c *gin.Context) {
	var commRsp NoticeCommResponse
	var addReq NoticeAddOneRequest
	err := c.BindJSON(&addReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	if addReq.TestOnly {
		// only test
		var testResult NoticeConnectTestResult
		err = CheckNoticeMsgConfig(addReq.MsgType, addReq.Type, &addReq.MsgConfig, true)
		if err != nil {
			testResult.Status = -1
			testResult.ErrMsg = err.Error()
		} else {
			testResult.Status = 0
			testResult.ErrMsg = ""
		}
		commRsp.TestResult = &testResult
		CreateResponse(c, common.SuccessCode, commRsp)
		return
	}

	err = CheckNoticeMsgConfig(addReq.MsgType, addReq.Type, &addReq.MsgConfig, false)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	user, userOk := c.Get("user")
	if !userOk {
		CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user info")
		return
	}

	nowTime := time.Now().Unix()
	var oneData outputer.NoticeConfigDbDataContent
	oneData.Type = addReq.Type
	oneData.MsgConfig = addReq.MsgConfig
	oneData.MsgType = addReq.MsgType
	oneData.LevelList = addReq.LevelList
	oneData.UpdateUser = user.(string)
	oneData.UpdateTime = nowTime
	oneData.Status = outputer.ConfigOutputerOpen
	oneData.Desc = GetNoticeDesc(addReq.Type)
	oneData.Abstract = GetNoticeAbstract(addReq.MsgType, &addReq.MsgConfig)

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	_, err = collection.InsertOne(c, oneData)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, commRsp)
}

func DelOneNoticeConfig(c *gin.Context) {
	var commRsp NoticeCommResponse
	var delReq NoticeDelOneRequest
	err := c.BindJSON(&delReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	nid, oErr := primitive.ObjectIDFromHex(delReq.NoticeId)
	if oErr != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, oErr.Error())
		return
	}

	queryJS := bson.M{"_id": bson.M{"$eq": nid}}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	_, err = collection.DeleteOne(c, queryJS)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	commRsp.NoticeId = &delReq.NoticeId
	CreateResponse(c, common.SuccessCode, commRsp)
}

func ModifyOneNoticeConfig(c *gin.Context) {
	var commRsp NoticeCommResponse
	var modifyReq NoticeModifyOneRequest
	err := c.BindJSON(&modifyReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	user, userOk := c.Get("user")
	if !userOk {
		CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user info")
		return
	}

	if modifyReq.TestOnly {
		// test and return
		var testResult NoticeConnectTestResult
		err = CheckNoticeMsgConfig(modifyReq.MsgType, modifyReq.Type, &modifyReq.MsgConfig, true)
		if err != nil {
			testResult.Status = -1
			testResult.ErrMsg = err.Error()
		} else {
			testResult.Status = 0
			testResult.ErrMsg = ""
		}
		commRsp.TestResult = &testResult
		CreateResponse(c, common.SuccessCode, commRsp)
		return
	} else {
		err = CheckNoticeMsgConfig(modifyReq.MsgType, modifyReq.Type, &modifyReq.MsgConfig, false)
		if err != nil {
			CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
			return
		}
	}

	nid, oErr := primitive.ObjectIDFromHex(modifyReq.NoticeId)
	if oErr != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, oErr.Error())
		return
	}

	// get old record first

	// update one
	queryJS := bson.M{"_id": nid}
	var oneData outputer.NoticeConfigDbDataContent
	oneData.MsgConfig = modifyReq.MsgConfig
	oneData.MsgType = modifyReq.MsgType
	oneData.LevelList = modifyReq.LevelList
	oneData.Type = modifyReq.Type
	oneData.Status = outputer.ConfigOutputerOpen
	oneData.UpdateUser = user.(string)
	oneData.UpdateTime = time.Now().Unix()
	oneData.Desc = GetNoticeDesc(modifyReq.Type)
	oneData.Abstract = GetNoticeAbstract(modifyReq.MsgType, &modifyReq.MsgConfig)

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	_, err = collection.ReplaceOne(c, queryJS, oneData)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	commRsp.NoticeId = &modifyReq.NoticeId
	CreateResponse(c, common.SuccessCode, commRsp)
}

func GetOneNoticeConfig(c *gin.Context) {
	noticeId := c.Param("id")
	if noticeId == "" {
		qErr := errors.New("notice_id is empty")
		CreateResponse(c, common.ParamInvalidErrorCode, qErr.Error())
		return
	}

	nid, oErr := primitive.ObjectIDFromHex(noticeId)
	if oErr != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, oErr.Error())
		return
	}

	var oneData outputer.NoticeConfigDbDataFormat
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	queryJS := bson.M{"_id": bson.M{"$eq": nid}}
	err := collection.FindOne(c, queryJS).Decode(&oneData)
	if err != nil {
		CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	CreateResponse(c, common.SuccessCode, oneData)
}

func ChangeOneNoticeRunConfig(c *gin.Context) {
	var commRsp NoticeCommResponse
	var changeReq NoticeOneChangeRunConfigRequest
	err := c.BindJSON(&changeReq)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	user, userOk := c.Get("user")
	if !userOk {
		CreateResponse(c, common.ParamInvalidErrorCode, "cannot get user info")
		return
	}

	nid, oErr := primitive.ObjectIDFromHex(changeReq.NoticeId)
	if oErr != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, oErr.Error())
		return
	}

	if changeReq.Opt == nil && len(changeReq.LevelList) == 0 {
		CreateResponse(c, common.ParamInvalidErrorCode, "empty request body")
		return
	}

	updateContent := bson.M{
		"update_user": user,
		"update_time": time.Now().Unix(),
	}
	if changeReq.Opt != nil {
		updateContent["status"] = *changeReq.Opt
	}

	if len(changeReq.LevelList) > 0 {
		updateContent["notice_level_list"] = changeReq.LevelList
	}

	updateJs := bson.M{"$set": updateContent}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	queryJS := bson.M{"_id": nid}
	_, err = collection.UpdateOne(c, queryJS, updateJs)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	commRsp.NoticeId = &changeReq.NoticeId

	CreateResponse(c, common.SuccessCode, commRsp)
}

func GetNoticePluginNameList(c *gin.Context) {
	var rsp = make([]string, 0, 10)

	CreateResponse(c, common.SuccessCode, rsp)
}
