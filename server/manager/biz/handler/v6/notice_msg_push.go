package v6

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/kafka"
	"github.com/bytedance/Elkeid/server/manager/internal/outputer"
	es7 "github.com/olivere/elastic/v7"
)

// ********************************* struct *********************************
type NoticeReminderMsgContent struct {
	Name       string `json:"name"`
	ExpireTime int64  `json:"expire_time"`
}

type NoticeMsgData struct {
	AlertType string                     `json:"alert_type_us,omitempty"`
	RuleName  string                     `json:"rule_name,omitempty"`
	HostName  string                     `json:"hostname,omitempty"`
	Timestamp string                     `json:"time,omitempty"`
	Service   []NoticeReminderMsgContent `json:"service,omitempty"`
}

type HubFeishuMsgFormat struct {
	AppID string `json:"AppID"`
}

// ********************************* function *********************************
func tarnsNoticeMsgDataToMap(msg *NoticeMsgData, notice_type string) map[string]interface{} {
	var retData = make(map[string]interface{})

	switch notice_type {
	case outputer.HubPluginMsgTypeAlarm:
		retData = map[string]interface{}{
			"alert_type": msg.AlertType,
			"rule_name":  msg.RuleName,
			"hostname":   msg.HostName,
			"timestamp":  msg.Timestamp,
		}
	case outputer.HubPluginMsgTypeReminder:
		retData = map[string]interface{}{
			"service": msg.Service,
		}
	}

	return retData
}

// ********************************* push msg function *********************************
func NoticePushMsgToFeishuByHub(msg *NoticeMsgData, notice_type string,
	config *outputer.NoticeMsgConfigFeishu) error {

	// trans struct to map
	outData := tarnsNoticeMsgDataToMap(msg, notice_type)

	var data = outputer.HubPluginPushMsgRequest{
		PluginType: "Action",
		PluginName: "SendToLarkGroup",
		Config:     make(map[string]string),
		Data:       outData,
	}

	data.Config["WebHookUrl"] = config.WebHookUrl
	if config.Seceret != "" {
		data.Config["Secret"] = config.Seceret
	}
	data.Config["type"] = notice_type
	// return outputer.RequestHubPluginByLeader(&data)
	return outputer.RequestHubPluginByHub(&data)
}

func NoticePushMsgToDingdingByHub(msg *NoticeMsgData, notice_type string,
	config *outputer.NoticeMsgConfigDingding) error {
	outData := tarnsNoticeMsgDataToMap(msg, notice_type)

	var data = outputer.HubPluginPushMsgRequest{
		PluginType: "Action",
		PluginName: "SendToDingdingGroup",
		Config:     make(map[string]string),
		Data:       outData,
	}

	data.Config["WebHookUrl"] = config.WebHookUrl
	if config.Seceret != "" {
		data.Config["Secret"] = config.Seceret
	}
	data.Config["type"] = notice_type
	//return outputer.RequestHubPluginByLeader(&data)
	return outputer.RequestHubPluginByHub(&data)
}

func NoticePushMsgToEWechatByHub(msg *NoticeMsgData, notice_type string,
	config *outputer.NoticeMsgConfigEnterpriseWechat) error {
	outData := tarnsNoticeMsgDataToMap(msg, notice_type)

	var data = outputer.HubPluginPushMsgRequest{
		PluginType: "Action",
		PluginName: "SendToWeCom",
		Config:     make(map[string]string),
		Data:       outData,
	}

	data.Config["WebHookUrl"] = config.WebHookUrl
	data.Config["type"] = notice_type
	// return outputer.RequestHubPluginByLeader(&data)
	return outputer.RequestHubPluginByHub(&data)
}

func NoticePushMsgToCustomByHub(msg *NoticeMsgData, notice_type string,
	config *outputer.NoticeMsgConfigCustom) error {
	outData := tarnsNoticeMsgDataToMap(msg, notice_type)

	var data = outputer.HubPluginPushMsgRequest{
		PluginType: "Action",
		PluginName: config.PluginName,
		Config:     config.CustomConfig,
		Data:       outData,
	}
	data.Config["type"] = notice_type
	// return outputer.RequestHubPluginByLeader(&data)
	return outputer.RequestHubPluginByHub(&data)
}

func NoticePushMsgToEmailByHub(msg *NoticeMsgData, notice_type string,
	config *outputer.NoticeMsgConfigEmail) error {
	outData := tarnsNoticeMsgDataToMap(msg, notice_type)

	var data = outputer.HubPluginPushMsgRequest{
		PluginType: "Action",
		PluginName: "SendSMTPEmail",
		Config:     make(map[string]string),
		Data:       outData,
	}

	data.Config["Server"] = config.Server
	data.Config["UserName"] = config.UserName
	data.Config["Password"] = config.Password
	data.Config["ToEmail"] = strings.Join(config.ToEmail, ";")
	data.Config["type"] = notice_type

	//return outputer.RequestHubPluginByLeader(&data)
	return outputer.RequestHubPluginByHub(&data)
}

// ********************************* test function *********************************
func TestNoticePushMsgToFeishuByHub(config *outputer.NoticeMsgConfigFeishu,
	notice_type string, need_test bool) error {
	if config == nil {
		return errors.New("empty config for feishu")
	}

	if need_test {
		var testMsg = NoticeMsgData{
			AlertType: "飞书",
			RuleName:  "发送测试",
			HostName:  "00-00-00-00",
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Service:   make([]NoticeReminderMsgContent, 0, 1),
		}

		testMsg.Service = append(testMsg.Service,
			NoticeReminderMsgContent{Name: "发送测试", ExpireTime: time.Now().Unix()})

		return NoticePushMsgToFeishuByHub(&testMsg, notice_type, config)
	}

	return nil
}

func TestNoticePushMsgToDingdingByHub(config *outputer.NoticeMsgConfigDingding,
	notice_type string, need_test bool) error {
	if config == nil {
		return errors.New("empty config for dingding")
	}

	if need_test {
		var testMsg = NoticeMsgData{
			AlertType: "钉钉",
			RuleName:  "发送测试",
			HostName:  "00-00-00-00",
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Service:   make([]NoticeReminderMsgContent, 0, 1),
		}

		testMsg.Service = append(testMsg.Service,
			NoticeReminderMsgContent{Name: "发送测试", ExpireTime: time.Now().Unix()})

		return NoticePushMsgToDingdingByHub(&testMsg, notice_type, config)
	}

	return nil
}

func TestNoticePushMsgToEWechatByHub(config *outputer.NoticeMsgConfigEnterpriseWechat,
	notice_type string, need_test bool) error {
	if config == nil {
		return errors.New("empty config for enterprise wechat")
	}

	if need_test {
		var testMsg = NoticeMsgData{
			AlertType: "企业微信",
			RuleName:  "发送测试",
			HostName:  "00-00-00-00",
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Service:   make([]NoticeReminderMsgContent, 0, 1),
		}

		testMsg.Service = append(testMsg.Service,
			NoticeReminderMsgContent{Name: "发送测试", ExpireTime: time.Now().Unix()})

		return NoticePushMsgToEWechatByHub(&testMsg, notice_type, config)
	}

	return nil
}

func TestNoticePushMsgToEmailByHub(config *outputer.NoticeMsgConfigEmail,
	notice_type string, need_test bool) error {
	if config == nil {
		return errors.New("empty config for email")
	}

	if need_test {
		var testMsg = NoticeMsgData{
			AlertType: "电子邮件",
			RuleName:  "发送测试",
			HostName:  "00-00-00-00",
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Service:   make([]NoticeReminderMsgContent, 0, 1),
		}

		testMsg.Service = append(testMsg.Service,
			NoticeReminderMsgContent{Name: "发送测试", ExpireTime: time.Now().Unix()})

		return NoticePushMsgToEmailByHub(&testMsg, notice_type, config)
	}

	return nil
}

func TestNoticePushMsgToSysLog(config *outputer.NoticeMsgConfigSyslog, need_test bool) error {
	if config == nil {
		return errors.New("empty config for syslog")
	}

	// check config

	// check connect
	if need_test {
		_, err := outputer.InitSyslogConnect(config)
		if err != nil {
			return err
		}

	}

	return nil
}

func TestNoticePushMsgToEs(config *outputer.NoticeMsgConfigEs, need_test bool) error {
	if config == nil {
		return errors.New("empty config for es")
	}

	if need_test {
		_, err := es7.NewClient(
			es7.SetURL(config.ESHost...),
			es7.SetBasicAuth(config.ESAuthUser, config.ESAuthPasswd),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func TestNoticePushMsgToKafka(config *outputer.NoticeMsgConfigKafka, need_test bool) error {
	if config == nil {
		return errors.New("empty config for kafka")
	}

	var oConf = make(map[string]interface{}, 0)
	if strings.TrimSpace(config.KafkaOtherConf) != "" {
		err := json.Unmarshal([]byte(config.KafkaOtherConf), &oConf)
		if err != nil {
			return err
		}
	}

	if need_test {
		stopChan := make(chan bool)
		_, err := kafka.NewProducer(config.KafkaBootstrapServers, oConf, "elkeid_kafka_oupter_test", stopChan)
		if err != nil {
			return err
		}
		close(stopChan)
	}

	return nil
}

func TestNoticePushMsgToCustomByHub(config *outputer.NoticeMsgConfigCustom,
	notice_type string, need_test bool) error {
	if config == nil {
		return errors.New("empty config for custom config")
	}

	if need_test {
		var testMsg = NoticeMsgData{
			AlertType: "自定义插件",
			RuleName:  "连接测试",
			HostName:  "00-00-00-00",
			Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			Service:   make([]NoticeReminderMsgContent, 0, 1),
		}

		testMsg.Service = append(testMsg.Service,
			NoticeReminderMsgContent{Name: "发送测试", ExpireTime: time.Now().Unix()})

		return NoticePushMsgToCustomByHub(&testMsg, notice_type, config)
	}

	return nil
}
