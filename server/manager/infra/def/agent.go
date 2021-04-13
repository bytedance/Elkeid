package def

const DefaultConfigVersion = 0
const DefaultAgentConfig = "agent_config"

type SrvConnStatResp struct {
	Code int            `json:"code"`
	Msg  string         `json:"msg"`
	Data []*AgentHBInfo `json:"data"`
}

type SrvConnListResp struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data []string `json:"data"`
}

type AgentTaskMsg struct {
	Name  string `json:"name"`
	Data  string `json:"data"`
	Token string `json:"token,omitempty"`
}

type AgentConfigMsg struct {
	Name        string   `json:"name" binding:"required"`
	Version     string   `json:"version,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	DownloadURL []string `json:"download_url,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}

type AgentHBInfo struct {
	Addr              string   `json:"addr" bson:"addr" `
	AgentId           string   `json:"agent_id" bson:"agent_id"`
	Cpu               float64  `json:"cpu" bson:"cpu"`
	CreateAt          int64    `json:"create_at" bson:"create_at"`
	LastHeartbeatTime int64    `json:"last_heartbeat_time" bson:"last_heartbeat_time"`
	Memory            int64    `json:"memory" bson:"memory"`
	NetType           string   `json:"net_type" bson:"net_type"`
	Version           string   `json:"version" bson:"version"`
	IntranetIPv4      []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	IntranetIPv6      []string `json:"intranet_ipv6" bson:"intranet_ipv6"`
	ExtranetIPv4      []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	ExtranetIPv6      []string `json:"extranet_ipv6" bson:"extranet_ipv6"`
	HostName          string   `json:"hostname" bson:"hostname"`
	SourceIp          string   `json:"source_ip" bson:"source_ip"`
	SourcePort        int64    `json:"source_port" bson:"source_port"`
	Tags              []string `json:"tags" bson:"tags"`

	Config           []AgentConfigMsg `json:"config,omitempty" bson:"config"`
	ConfigUpdateTime int64            `json:"config_update_time,omitempty" bson:"config_update_time"`

	IO     float64                  `json:"io" bson:"io"`
	Slab   int64                    `json:"slab" bson:"slab"`
	Plugin []map[string]interface{} `json:"plugins" bson:"plugins"`
}

type DefaultConfig struct {
	Type       string           `json:"type" bson:"type" binding:"required"`
	Version    int              `json:"version" bson:"version"`
	Config     []AgentConfigMsg `json:"config" bson:"config" binding:"required"`
	CreateTime int64            `json:"create_time" bson:"create_time"`
	UpdateTime int64            `json:"update_time" bson:"update_time"`
}

type AgentSubTask struct {
	AgentID    string `json:"agent_id" bson:"agent_id" `
	TaskID     string `json:"task_id" bson:"task_id" `
	Name       string `json:"name" bson:"name"`
	Data       string `json:"data" bson:"data"`
	Token      string `json:"token" bson:"token"`
	Status     string `json:"status" bson:"status"`
	UpdateTime int64  `json:"update_time" bson:"update_time"`
	TaskResult string `json:"task_result" bson:"task_result"`
}
