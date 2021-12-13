package def

const DefaultConfigVersion = 0
const DefaultAgentConfig = "agent_config"

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
	Token    string `json:"token,omitempty" bson:"token"`
	DataType int32  `json:"data_type,omitempty" bson:"data_type"`
}

type AgentConfigMsg struct {
	Name        string   `json:"name" binding:"required" bson:"name"`
	Type        string   `json:"type,omitempty" bson:"type"`
	Signature   string   `json:"signature,omitempty" bson:"signature"`
	Version     string   `json:"version,omitempty" bson:"version"`
	SHA256      string   `json:"sha256,omitempty" bson:"sha256"`
	DownloadURL []string `json:"download_url,omitempty" bson:"download_url"`
	Detail      string   `json:"detail,omitempty" bson:"detail"`
}

type AgentHBInfo struct {
	AgentId    string   `json:"agent_id" bson:"agent_id"`
	SourceIp   string   `json:"source_ip" bson:"source_ip"`
	SourcePort int64    `json:"source_port" bson:"source_port"`
	Tags       []string `json:"tags" bson:"tags"`
	PSMName    string   `json:"psm_name" bson:"psm_name"`
	PSMPath    string   `json:"psm_path" bson:"psm_path"`

	Config           []AgentConfigMsg `json:"config,omitempty" bson:"config"`
	ConfigUpdateTime int64            `json:"config_update_time,omitempty" bson:"config_update_time"`
}

type DefaultConfig struct {
	Type       string           `json:"type" bson:"type" binding:"required"`
	Version    int              `json:"version" bson:"version"`
	Config     []AgentConfigMsg `json:"config" bson:"config" binding:"required"`
	CreateTime int64            `json:"create_time" bson:"create_time"`
	UpdateTime int64            `json:"update_time" bson:"update_time"`
}

type DefaultVersionConfig struct {
	Type       string           `json:"type" bson:"type" binding:"required"`
	Version    string           `json:"version" bson:"version"`
	Config     []AgentConfigMsg `json:"config" bson:"config" binding:"required"`
	CreateTime int64            `json:"create_time" bson:"create_time"`
	UpdateTime int64            `json:"update_time" bson:"update_time"`
}

type AgentSubTask struct {
	TaskType   string                 `json:"task_type" bson:"task_type" `
	AgentID    string                 `json:"agent_id" bson:"agent_id" `
	TaskID     string                 `json:"task_id" bson:"task_id" `
	JobID      string                 `json:"job_id" bson:"job_id" `
	TaskData   map[string]interface{} `json:"task_data" bson:"task_data"`
	TaskUrl    string                 `json:"task_url" bson:"task_url"`
	Token      string                 `json:"token" bson:"token"`
	Status     string                 `json:"status" bson:"status"`
	UpdateTime int64                  `json:"update_time" bson:"update_time"`
	TaskResult string                 `json:"task_result" bson:"task_result"`
	TaskResp   string                 `json:"task_resp" bson:"task_resp"`
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
