package rasp

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"sync"
	"time"
)

type RaspConfigRule struct {
	Runtime   string   `json:"runtime" bson:"runtime"`
	HookFunc  []string `json:"hook_func" bson:"hook_func"`
	HookParam int      `json:"hook_param" bson:"hook_param"`
	Rules     []struct {
		Type string `json:"type" bson:"type"`
		Rule string `json:"rule" bson:"rule"`
	} `json:"rules" bson:"rules"`
}
type RaspConfig struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	User      string             `json:"user" bson:"user"`
	IfProtect bool               `json:"if_protect" bson:"if_protect"`
	IpList    []string           `json:"ip_list" bson:"ip_list"`
	Tag       string             `json:"tag" bson:"tag"`
	Cmd       string             `json:"cmd" bson:"cmd"`
	EnvList   []string           `json:"env_list" bson:"env_list"`
	AliveTime int                `json:"alive_time" bson:"alive_time"`
	Runtime   []string           `json:"runtime" bson:"runtime"`
	Block     []RaspConfigRule   `json:"block" bson:"block"`
	Filter    []RaspConfigRule   `json:"filter" bson:"filter"`
}
type RaspProcess struct {
	ExeName        string            `json:"exe_name" bson:"exe_name"`
	LastTime       int64             `json:"last_time" bson:"update_time"`
	Runtime        string            `json:"runtime" bson:"runtime"`
	ExtranetIpv4   []string          `json:"extranet_ipv4" bson:"extranet_ipv4"`
	IntranetIpv4   []string          `json:"intranet_ipv4" bson:"intranet_ipv4"`
	AgentId        string            `json:"agent_id" bson:"agent_id"`
	TraceState     string            `json:"status" bson:"trace_state"`
	Pid            string            `json:"pid" bson:"pid"`
	Hostname       string            `json:"hostname" bson:"hostname"`
	Cmdline        string            `json:"cmdline" bson:"cmdline"`
	RuntimeVersion string            `json:"runtime_version" bson:"runtime_version"`
	ProtectTime    string            `json:"protect_time" bson:"attach_end_time"`
	EnvironJson    map[string]string `json:"environ_json" bson:"environ_json"`
	Filter         string            `json:"filter" bson:"filter"`
	Block          string            `json:"block" bson:"block"`
	Limit          string            `json:"limit" bson:"limit"`
	Patch          string            `json:"patch" bson:"patch"`
}
type RaspMethod struct {
	Runtime       string `json:"runtime" bson:"runtime"`
	ClassId       int    `json:"class_id" bson:"class_id"`
	MethodId      int    `json:"method_id" bson:"method_id"`
	ClassName     string `json:"class_name" bson:"class_name"`
	MethodName    string `json:"method_name" bson:"method_name"`
	ProbeHook     string `json:"probe_hook" bson:"probe_hook"`
	MaxIndexCount int    `json:"max_index_count" bson:"max_index_count"`
	DefaultIndex  int    `json:"default_index" bson:"default_index"`
	ZhName        string `json:"zh_name" bson:"zh_name"`
}

// rasp心跳key数据
type RaspHeartBeat struct {
	Pid        string `json:"pid" bson:"pid"`
	AgentId    string `json:"agent_id" bson:"agent_id"`
	Runtime    string `json:"runtime" bson:"runtime"`
	ExeName    string `json:"exe_name" bson:"exe_name"`
	TraceState string `json:"trace_state" bson:"trace_state"`
}

// rasp探针key数据
type RaspProbeStruct struct {
	Pid     string `json:"pid" bson:"pid"`
	AgentId string `json:"agent_id" bson:"agent_id"`
	Filter  string `json:"filter" bson:"filter"`
	Block   string `json:"block" bson:"block"`
	Limit   string `json:"limit" bson:"limit"`
	Patch   string `json:"patch" bson:"patch"`
}

// 2997
type RaspHbType struct {
	DataType   string            `json:"data_type" bson:"data_type"`
	Tag        string            `json:"tags" bson:"tags"`
	AgentId    string            `json:"agent_id" bson:"agent_id"`
	Pid        string            `json:"pid" bson:"pid"`
	Env        map[string]string `json:"environ_json" bson:"environ_json"`
	Runtime    string            `json:"runtime" bson:"runtime"`
	Cmd        string            `json:"cmdline" bson:"cmdline"`
	Uptime     string            `json:"uptime" bson:"uptime"`
	Ipv4Data   string            `json:"in_ipv4_list" bson:"in_ipv4_list"`
	Exv4Data   string            `json:"ex_ipv4_list" bson:"ex_ipv4_list"`
	Ipv4List   []string          `json:"ipv4_list" bson:"ipv4_list"`
	Exv4List   []string          `json:"exv4_list" bson:"exv4_list"`
	TraceState string            `json:"trace_state" bson:"trace_state"`

	Filter string `json:"filter" bson:"filter"`
	Block  string `json:"block" bson:"block"`
	Patch  string `json:"patch" bson:"patch"`
	Limit  string `json:"limit" bson:"limit"`

	Action         string `json:"action" bson:"action"`
	Reason         string `json:"reason" bson:"reason"`
	TryAttachCount string `json:"try_attach_count" bson:"try_attach_count"`
}

type RaspTaskConfig struct {
	Id         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	User       string             `json:"user" bson:"user"`
	IfProtect  bool               `json:"if_protect" bson:"if_protect"`
	IpList     []string           `json:"ip_list" bson:"ip_list"`
	Tag        string             `json:"tag" bson:"tag"`
	Cmd        string             `json:"cmd" bson:"cmd"`
	EnvList    []string           `json:"env_list" bson:"env_list"`
	AliveTime  int                `json:"alive_time" bson:"alive_time"`
	Runtime    []string           `json:"runtime" bson:"runtime"`
	Block      []RaspConfigRule   `json:"block" bson:"block"`
	Filter     []RaspConfigRule   `json:"filter" bson:"filter"`
	EnvJson    map[string]string  `json:"env_json" bson:"env_json"`
	BlockUuid  string             `json:"block_uuid" bson:"block_uuid"`
	FilterUuid string             `json:"filter_uuid" bson:"filter_uuid"`
	LimitUuid  string             `json:"limit_uuid" bson:"limit_uuid"`
	PatchUuid  string             `json:"patch_uuid" bson:"patch_uuid"`
	TaskStr    string             `json:"task_str" bson:"task_str"`
}

type RaspProcessVuln struct {
	AgentId     string   `json:"agent_id" bson:"agent_id"`
	VulnId      int64    `json:"vuln_id" bson:"vuln_id"`
	VulnName    string   `json:"vuln_name" bson:"vuln_name"`
	Pid         string   `json:"pid" bson:"pid"`
	Cmd         string   `json:"cmd" bson:"cmd"`
	CveId       string   `json:"cve_id" bson:"cve_id"`
	Status      string   `json:"status" bson:"status"`
	Level       string   `json:"level" bson:"level"`
	Tag         []string `json:"tag" bson:"tag"`
	CreateTime  int64    `json:"create_time" bson:"create_time"`
	UpdateTime  int64    `json:"update_time" bson:"update_time"`
	ControlTime int64    `json:"control_time" bson:"control_time"`
}

const (
	RaspStateAttached  = "ATTACHED"
	RaspStateInspected = "INSPECTED"
	RaspStateWaitAtt   = "WAIT_ATTACH"
	RaspStateClose     = "CLOSING"
	RaspStateWaitIns   = "WAIT_INSPECT"
	RaspStateAttFail   = "WAIT_ATTACH_failed"

	RaspRuntimePython = "Python"
	RaspRuntimeJava   = "Java"
	RaspRuntimePhp    = "PHP"
	RaspRuntimeNodeJS = "NodeJS"
	RaspRuntimeGolang = "Golang"
	HeartBeartPython  = "CPython"
	HeartBeartJava    = "JVM"
	HeartBeartPhp     = "PHP"
	HeartBeartNodeJS  = "NodeJS"
	HeartBeartGolang  = "Golang"
	RaspTaskDataType  = 2005
	RaspVulnUnSafe    = "unsafe"
	RaspVulnHotFix    = "hotfix"
)

var (
	raspCacheTimeout  = 1 * time.Hour
	runtimeConfigList = []string{"Golang", "JVM", "PHP", "CPython", "NodeJS"}
	taskLock          sync.RWMutex
	configLock        sync.Mutex
)
