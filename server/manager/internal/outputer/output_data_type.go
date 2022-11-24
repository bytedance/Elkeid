package outputer

type NoticeMsgConfigFeishu struct {
	WebHookUrl string `json:"web_hook_url" bson:"web_hook_url"`
	Seceret    string `json:"seceret,omitempty" bson:"seceret,omitempty"`
	Remarks    string `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigDingding struct {
	WebHookUrl string `json:"web_hook_url" bson:"web_hook_url"`
	Seceret    string `json:"seceret,omitempty" bson:"seceret,omitempty"`
	Remarks    string `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigEnterpriseWechat struct {
	WebHookUrl string `json:"web_hook_url" bson:"web_hook_url"`
	Remarks    string `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigEmail struct {
	Server   string   `json:"server" bson:"server"`
	UserName string   `json:"user_name" bson:"user_name"`
	Password string   `json:"password" bson:"password"`
	ToEmail  []string `json:"to_email" bson:"to_email"`
	Remarks  string   `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigKafka struct {
	KafkaBootstrapServers string `json:"server" bson:"server"`
	KafkaTopic            string `json:"topic" bson:"topic"`
	KafkaOtherConf        string `json:"other_config,omitempty" bson:"other_config,omitempty"`
	Remarks               string `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigEs struct {
	ESHost             []string `json:"es_host" bson:"es_host"`
	ESIndex            string   `json:"es_index" bson:"es_index"`
	ESAuthUser         string   `json:"es_auth_user" bson:"es_auth_user"`
	ESAuthPasswd       string   `json:"es_auth_passwd" bson:"es_auth_passwd"`
	ESIndexRefreshType string   `json:"es_index_refresh_type" bson:"es_index_refresh_type"`
	Remarks            string   `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigSyslog struct {
	SyslogServer string `json:"syslog_server" bson:"syslog_server"`
	Protocol     string `json:"protocol" bson:"protocol"`
	Facility     int    `json:"facility" bson:"facility"`
	Remarks      string `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfigCustom struct {
	PluginName   string            `json:"plugin_name" bson:"plugin_name"`
	CustomConfig map[string]string `json:"custom_config" bson:"custom_config"`
	Remarks      string            `json:"remarks,omitempty" bson:"remarks,omitempty"`
}

type NoticeMsgConfig struct {
	FeishuConfig   *NoticeMsgConfigFeishu           `json:"feishu_config,omitempty" bson:"feishu_config,omitempty"`
	DingdingConfig *NoticeMsgConfigDingding         `json:"dingding_config,omitempty" bson:"dingding_config,omitempty"`
	EWechat        *NoticeMsgConfigEnterpriseWechat `json:"enterprise_wechat,omitempty" bson:"enterprise_wechat,omitempty"`
	Syslog         *NoticeMsgConfigSyslog           `json:"syslog,omitempty" bson:"syslog,omitempty"`
	Email          *NoticeMsgConfigEmail            `json:"email,omitempty" bson:"email,omitempty"`
	Kafka          *NoticeMsgConfigKafka            `json:"kafka,omitempty" bson:"kafka,omitempty"`
	ES             *NoticeMsgConfigEs               `json:"elasticsearch,omitempty" bson:"elasticsearch,omitempty"`
	Custom         *NoticeMsgConfigCustom           `json:"custom,omitempty" bson:"custom,omitempty"`
}

type NoticeRunConfig struct {
	NoticeId   *string  `json:"notice_id,omitempty" bson:"notice_id,omitempty"`
	Type       string   `json:"notice_type" bson:"notice_type"`
	LevelList  []string `json:"notice_level_list" bson:"notice_level_list"`
	Status     int      `json:"status" bson:"status"`
	MsgType    string   `json:"notice_config_type" bson:"notice_config_type"`
	Abstract   string   `json:"notice_config_abstract" bson:"notice_config_abstract"`
	Desc       string   `json:"notice_type_desc" bson:"notice_type_desc"`
	UpdateTime int64    `json:"update_time" bson:"update_time"`
	UpdateUser string   `json:"update_user" bson:"update_user"`
}

type NoticeConfigDbDataContent struct {
	NoticeRunConfig `json:",inline" bson:",inline"`
	MsgConfig       NoticeMsgConfig `json:"notice_config" bson:"notice_config"`
}

type NoticeConfigDbDataFormat struct {
	ID                        string `json:"_id" bson:"_id"`
	NoticeConfigDbDataContent `json:",inline" bson:",inline"`
}

type OutputerConfig struct {
	NoticeConfigDbDataFormat `json:",inline" bson:",inline"`
}

type HubPluginPushMsgRequest struct {
	PluginType string            `json:"plugin_type"`
	PluginName string            `json:"plugin_name"`
	Type       string            `json:"type"`
	Config     map[string]string `json:"config"`
	Data       interface{}       `json:"data"`
	//Data       NoticeMsgData     `json:"data"`
}

type HubPluginPushMsgResponse struct {
	Success  bool        `json:"success"`
	Data     interface{} `json:"data"`
	ErrorMsg string      `json:"errormsg"`
}

type HubPluginPushMsgResponseSucessData struct {
	Done bool `json:"done"`
}
