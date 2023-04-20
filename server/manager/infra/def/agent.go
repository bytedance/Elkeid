package def

type ConnSimpleStat struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
}

type SrvConnStatResp struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data []*ConnStat `json:"data"`
}

type SrvConnStatRespV2 struct {
	Code int                      `json:"code"`
	Msg  string                   `json:"msg"`
	Data []map[string]interface{} `json:"data"`
}

type ConnStat struct {
	AgentInfo   map[string]interface{}   `json:"agent_info"`
	PluginsInfo []map[string]interface{} `json:"plugins_info"`
}

type SrvConnListResp struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data []string `json:"data"`
}

type AgentTaskMsg struct {
	Name     string `json:"name" bson:"name"`
	Data     string `json:"data" bson:"data"`
	Token    string `json:"token" bson:"token"`
	DataType int32  `json:"data_type" bson:"data_type"`
}

type AgentConfigMsg struct {
	Name        string   `json:"name" binding:"required" bson:"name"`
	Type        string   `json:"type" bson:"type"`
	Signature   string   `json:"signature" bson:"signature"`
	Version     string   `json:"version" bson:"version"`
	SHA256      string   `json:"sha256" bson:"sha256"`
	DownloadURL []string `json:"download_url" bson:"download_url"`
	Detail      string   `json:"detail" bson:"detail"`
}

type AgentHBInfo struct {
	AgentId    string   `json:"agent_id" bson:"agent_id"`
	SourceIp   string   `json:"source_ip" bson:"source_ip"`
	SourcePort int64    `json:"source_port" bson:"source_port"`
	Tags       []string `json:"tags" bson:"tags"`
	PSMName    string   `json:"psm_name" bson:"psm_name"`
	PSMPath    string   `json:"psm_path" bson:"psm_path"`
	Enhanced   bool     `json:"enhanced" bson:"enhanced"`

	Config           []AgentConfigMsg `json:"config,omitempty" bson:"config"`
	ConfigUpdateTime int64            `json:"config_update_time,omitempty" bson:"config_update_time"`
}

type SvrResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

type IDListReq struct {
	IDList []string `json:"id_list" binding:"required"`
}

type AgentQuickTask struct {
	AgentID string        `json:"agent_id" bson:"agent_id" binding:"required"`
	Command ConfigRequest `json:"command" bson:"command" binding:"required"`
}

type ConfigRequest struct {
	AgentCtrl int              `json:"agent_ctrl,omitempty"`
	Task      AgentTaskMsg     `json:"task,omitempty"`
	Config    []AgentConfigMsg `json:"config,omitempty"`
}

type ComponentRes struct {
	Name    string
	Version string
	Result  string
}
