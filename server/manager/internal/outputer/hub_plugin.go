package outputer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"strings"
)

type LeaderAuthRequest struct {
	Username string `json:"username" bson:"username" binding:"required"`
	Password string `json:"password" bson:"password" binding:"required"`
}

const (
	HubPluginMsgTypeAlarm    string = "alert"
	HubPluginMsgTypeReminder string = "reminder"
)

func RequestHubPluginByHub(req *HubPluginPushMsgRequest) error {
	hubPluginReq := TestPluginReq{
		PluginType: req.PluginType,
		PluginName: req.PluginName,
		Config:     req.Config,
		Data:       req.Data,
		Sha256Sum:  "",
	}

	data, err := ApplyHubPlugin(hubPluginReq)
	if err != nil {
		return err
	}

	// decode data
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var dataInfo map[string]interface{}
	err = json.Unmarshal(dataBytes, &dataInfo)
	if err != nil {
		return err
	}

	dataRsp, dOk := dataInfo["resp"]
	if !dOk {
		errMsg := fmt.Sprintf("ApplyHubPlugin response no 'resp' key %+v", dataRsp)
		return errors.New(errMsg)
	}

	switch dataRsp.(type) {
	case map[string]interface{}:
		ylog.Debugf("ApplyHubPlugin response success", "%+v", dataRsp)
	default:
		errMsg := fmt.Sprintf("ApplyHubPlugin response err %+v", dataRsp)
		return errors.New(errMsg)
	}

	dataRspMap, dOk := dataRsp.(map[string]interface{})
	if !dOk {
		errMsg := fmt.Sprintf("ApplyHubPlugin response type err %+v", dataRsp)
		return errors.New(errMsg)
	}

	done, dOk := dataRspMap["done"]
	if !dOk {
		errMsg := fmt.Sprintf("ApplyHubPlugin response no 'done' key %+v", dataRspMap)
		return errors.New(errMsg)
	}

	doneValue, dOk := done.(bool)
	if !dOk {
		errMsg := fmt.Sprintf("ApplyHubPlugin response 'done' type wrong %+v", done)
		return errors.New(errMsg)
	}

	if !doneValue {
		errMsg := fmt.Sprintf("ApplyHubPlugin response is %t", doneValue)
		return errors.New(errMsg)
	}

	ylog.Debugf("ApplyHubPlugin success", "%t", doneValue)

	return nil
}

// worker
type HubPluginWorker struct {
	level_map     map[string]int
	msg_type      string
	plugin_name   string
	plugin_config map[string]string
	Queue         chan *DataModel
}

func (b *HubPluginWorker) ReadConfig(config NoticeMsgConfig, pluginMsgType string) error {
	var hubPluginConfig = make(map[string]string)

	if config.FeishuConfig != nil {
		b.plugin_name = "SendToLarkGroup"
		hubPluginConfig["WebHookUrl"] = config.FeishuConfig.WebHookUrl
		hubPluginConfig["Secret"] = config.FeishuConfig.Seceret
		hubPluginConfig["type"] = pluginMsgType
		b.plugin_config = hubPluginConfig
		return nil
	}

	if config.DingdingConfig != nil {
		b.plugin_name = "SendToDingdingGroup"
		hubPluginConfig["WebHookUrl"] = config.DingdingConfig.WebHookUrl
		hubPluginConfig["Secret"] = config.DingdingConfig.Seceret
		hubPluginConfig["type"] = pluginMsgType
		b.plugin_config = hubPluginConfig
		return nil
	}

	if config.EWechat != nil {
		b.plugin_name = "SendToWeCom"
		hubPluginConfig["WebHookUrl"] = config.EWechat.WebHookUrl
		hubPluginConfig["type"] = pluginMsgType
		b.plugin_config = hubPluginConfig
		return nil
	}

	if config.Email != nil {
		b.plugin_name = "SendSMTPEmail"
		hubPluginConfig["Server"] = config.Email.Server
		hubPluginConfig["UserName"] = config.Email.UserName
		hubPluginConfig["Password"] = config.Email.Password
		hubPluginConfig["ToEmail"] = strings.Join(config.Email.ToEmail, ";")
		hubPluginConfig["type"] = pluginMsgType
		b.plugin_config = hubPluginConfig
		return nil
	}

	if config.Custom != nil {
		b.plugin_name = config.Custom.PluginName
		b.plugin_config = config.Custom.CustomConfig
		b.plugin_config["type"] = pluginMsgType
		return nil
	}

	return errors.New("no valid config for HubPluginWorker")
}

func (b *HubPluginWorker) Init(conf *OutputerConfig) error {
	if conf == nil {
		return errors.New("empty config for HubPluginWorker")
	}

	if conf.Type == "" {
		return errors.New("empty type for HubPluginWorker")
	}

	pluginMsgType := ""
	switch conf.Type {
	case DataModelHidsAlarm:
		pluginMsgType = HubPluginMsgTypeAlarm
	case DataModelAuthorizationExpire:
		pluginMsgType = HubPluginMsgTypeReminder
	case DataModelRaspAlarm:
		pluginMsgType = HubPluginMsgTypeAlarm
	case DataModelKubeAlarm:
		pluginMsgType = HubPluginMsgTypeAlarm
	case DataModelVirusAlarm:
		pluginMsgType = HubPluginMsgTypeAlarm
	default:
		errMsg := fmt.Sprintf("unkown msg type for hub plugin %s", conf.Type)
		return errors.New(errMsg)
	}

	b.msg_type = conf.Type
	b.level_map = make(map[string]int)
	for _, one := range conf.LevelList {
		b.level_map[one] = 1
	}

	err := b.ReadConfig(conf.MsgConfig, pluginMsgType)
	if err != nil {
		return err
	}

	// make channel
	b.Queue = make(chan *DataModel, ConfigOutputerQueueMax)

	go b.WaitForInputMsg()

	return nil
}

func (b *HubPluginWorker) HitModel(model DataHitModelInfo) bool {

	if model.Model == b.msg_type {
		if len(b.level_map) > 0 {
			_, ok := b.level_map[model.Level]
			if ok {
				return true
			}
		} else {
			return true
		}
	}

	return false
}

func (b *HubPluginWorker) WaitForInputMsg() {
	for {
		if d, ok := <-b.Queue; ok {
			if d != nil {
				ylog.Debugf("HubPluginWorker SendMsg", "%#v", d)
				pluginMsgType := ""
				switch d.HitModel.Model {
				case DataModelHidsAlarm:
					pluginMsgType = HubPluginMsgTypeAlarm
				case DataModelAuthorizationExpire:
					pluginMsgType = HubPluginMsgTypeReminder
				case DataModelRaspAlarm:
					pluginMsgType = HubPluginMsgTypeAlarm
				case DataModelKubeAlarm:
					pluginMsgType = HubPluginMsgTypeAlarm
				case DataModelVirusAlarm:
					pluginMsgType = HubPluginMsgTypeAlarm
				default:
					ylog.Errorf("unkown plugin msg type", "%s", d.HitModel.Model)
					return
				}

				msg := HubPluginPushMsgRequest{
					PluginType: "Action",
					PluginName: b.plugin_name,
					Type:       pluginMsgType,
					Config:     b.plugin_config,
					Data:       d.Data,
				}

				// err := RequestHubPluginByLeader(&msg)
				err := RequestHubPluginByHub(&msg)
				if err != nil {
					ylog.Errorf("RequestHubPluginByHub error", err.Error())
				}
			}
		} else {
			ylog.Infof("stop HubPluginWorker for", "%s", b.plugin_name)
			return
		}
	}
}

func (b *HubPluginWorker) SendMsg(dm *DataModel) {
	if dm == nil {
		return
	}

	select {
	case b.Queue <- dm:
		return
	default:
		ylog.Errorf("channel blocked in HubPluginWorker for", "%s", b.plugin_name)
	}
}

func (b *HubPluginWorker) Close() {
	// close the channel
	close(b.Queue)
	return
}
