package v6

import (
	"github.com/bytedance/Elkeid/server/manager/internal/alarm"
)

const (
	AlarmSupportLanguageCn = "CN"
	AlarmSupportLangageEn  = "EN"
)

//goland:noinspection GoUnusedGlobalVariable
var AlarmSupportLangage = map[string]string{
	"en-US": AlarmSupportLangageEn,
	"zh-CN": AlarmSupportLanguageCn,
}

type AlarmListRequest struct {
	Name          string   `json:"name,omitempty"`
	Status        []int    `json:"status,omitempty"`
	LevelList     []string `json:"level,omitempty"`
	TypeList      []string `json:"type,omitempty"`
	DataType      string   `json:"data_type,omitempty"`
	TimeStart     int64    `json:"time_start,omitempty"`
	TimeEnd       int64    `json:"time_end,omitempty"`
	AgentId       string   `json:"agent_id,omitempty"`
	EventId       string   `json:"event_id,omitempty"`
	EventName     string   `json:"event_name,omitempty"`
	EventReason   string   `json:"event_reason,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	Ip            string   `json:"ip,omitempty"`
	ClusterId     string   `json:"cluster_id,omitempty"`
	ClusterRegion string   `json:"cluster_region,omitempty"`
	ClusterName   string   `json:"cluster_name,omitempty"`
	FilePath      string   `json:"file_path,omitempty"`
	FileHash      string   `json:"file_hash,omitempty"`
	TaskID        string   `json:"task_id,omitempty"`
}

type AlarmListItem struct {
	AlarmId     string                `json:"alarm_id"`
	Status      int                   `json:"status"`
	Type        string                `json:"type"`
	Name        string                `json:"name"`
	Level       string                `json:"level"`
	AlarmTime   int64                 `json:"alarm_time"`
	TraceId     string                `json:"trace_id"`
	EventId     string                `json:"event_id"`
	EventName   string                `json:"event_name"`
	Attribution []AlarmAttribution    `json:"attribution_list"`
	DataType    string                `json:"data_type"`
	AgentId     string                `json:"agent_id,omitempty"`
	HostName    string                `json:"alarm_hostname,omitempty"`
	Host        *AlarmHostInfo        `json:"host,omitempty"`
	Cluster     *KubeAlarmClusterInfo `json:"cluster,omitempty"`
	FilePath    string                `json:"file_path"`
	FileHash    string                `json:"file_hash"`
	ErrReason   string                `json:"error_reason,omitempty"`
}

type AlarmDetailDataBaseAgent struct {
	HostName   string   `json:"hostname"`
	InnerIPs   []string `json:"in_ip_list"`
	OuterIPs   []string `json:"out_ip_list"`
	AgentId    string   `json:"agent_id"`
	Os         string   `json:"os"`
	OsPlatform string   `json:"os_platform,omitempty"`
}

type AlarmDetailDataBaseAlarm struct {
	AlarmType    string   `json:"alarm_type"`
	AlarmLevel   string   `json:"level"`
	Status       int      `json:"status"`
	UpdateTime   int64    `json:"update_time"`
	Desc         string   `json:"desc"`
	Suggest      string   `json:"suggest"`
	Docker       string   `json:"docker"`
	CreateTime   int64    `json:"create_time"`
	HandlerUser  string   `json:"handle_user,omitempty"`
	HandlerTime  int64    `json:"handle_time,omitempty"`
	AttackIdList []string `json:"attack_id_list"`
	TraceId      string   `json:"trace_id,omitempty"`
	Name         string   `json:"name"`
}

type AlarmNewStatus struct {
	AlarmId     string `json:"alarm_id"`
	AlarmStatus int    `json:"alarm_status"`
}

type AlarmStatusUpdateRequest struct {
	Lists []AlarmNewStatus `json:"alarms"`
}

type AlarmStatusUpdateInfo struct {
	AlarmId string `json:"alarm_id"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
}

type AgentStatisticsRequest struct {
	AgentId   string `form:"agent_id"`
	ClusterId string `form:"cluster_id"`
}

type AgentStatisticsResponse struct {
	alarm.AlarmOverviewInfo `json:",inline"`
}

type AgentHbInfo struct {
	HostName        string   `json:"hostname" bson:"hostname"`
	Platform        string   `json:"platform" bson:"platform"`
	PlatformFamily  string   `json:"platform_family" bson:"platform_family"`
	PlatformVersion string   `json:"platform_version" bson:"platform_version"`
	InnerIPv4       []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	OuterIPv4       []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
}

type AlarmFilterByWhiteData struct {
	Total int64 `json:"total"`
}

type AlarmExportDataRequest struct {
	AlarmIdList *[]string               `json:"alarm_id_list"`
	Conditions  *alarm.AlarmQueryFilter `json:"conditions"`
}

type HubAlarmRuleInfo struct {
	RuleName    string `json:"RuleName" bson:"RuleName"`
	RuleType    string `json:"RuleType" bson:"RuleType"`
	HarmLevel   string `json:"HarmLevel" bson:"HarmLevel"`
	KillChainID string `json:"KillChainID" bson:"KillChainID"`
	Desc        string `json:"Desc" bson:"Desc"`
}

type HubAlarmInfo struct {
	RuleInfo HubAlarmRuleInfo `json:"RULE_INFO" bson:"RULE_INFO"`
}

type AlarmNodeDbData struct {
	AgentId         string `json:"agent_id" bson:"agent_id"`
	DataType        string `json:"data_type" bson:"data_type"`
	Pid             string `json:"pid" bson:"pid"`
	Exec            string `json:"exe" bson:"exe"`
	Argv            string `json:"argv" bson:"argv"`
	Ppid            string `json:"ppid" bson:"ppid"`
	PpidArgv        string `json:"ppid_argv" bson:"ppid_argv"`
	Pgid            string `json:"pgid" bson:"pgid"`
	PgidArgv        string `json:"pgid_argv" bson:"pgid_argv"`
	UserName        string `json:"username" bson:"username"`
	PidTree         string `json:"pid_tree" bson:"pid_tree"`
	SocketPid       string `json:"socket_pid" bson:"socket_pid"`
	SocketArgv      string `json:"socket_argv" bson:"socket_argv"`
	SshInfo         string `json:"ssh_info" bson:"ssh_info"`
	Ssh             string `json:"ssh" bson:"ssh"`
	Uid             string `json:"uid" bson:"uid"`
	Dip             string `json:"dip" bson:"dip"`
	Dport           string `json:"dport" bson:"dport"`
	Sip             string `json:"sip" bson:"sip"`
	Sport           string `json:"sport" bson:"sport"`
	TargeId         string `json:"target_pid" bson:"target_pid"`
	PtraceRequest   string `json:"ptrace_request" bson:"ptrace_request"`
	Query           string `json:"query" bson:"query"`
	FilePath        string `json:"file_path" bson:"file_path"`
	ModInfo         string `json:"mod_info" bson:"mod_info"`
	ModuleName      string `json:"module_name" bson:"module_name"`
	SyscallNumber   string `json:"syscall_number" bson:"syscall_number"`
	InterruptNumber string `json:"interrupt_number" bson:"interrupt_number"`
	Path            string `json:"path" bson:"path"`
	Types           string `json:"types" bson:"types"`
	User            string `json:"user" bson:"user"`
	OldUid          string `json:"old_uid,omitempty" bson:"old_uid,omitempty"`
	OldUserName     string `json:"old_username,omitempty" bson:"old_username,omitempty"`
	InDocker        string `json:"docker,omitempty" bson:"docker,omitempty"`
	TimeStamp       string `json:"timestamp,omitempty" bson:"timestamp,omitempty"`
	ExeHash         string `json:"exe_hash,omitempty" bson:"exe_hash,omitempty"`
	CreateTime      string `json:"create_at,omitempty" bson:"create_at,omitempty"`
	ModifyTime      string `json:"modify_at,omitempty" bson:"modify_at,omitempty"`
	PidSet          string `json:"pid_set,omitempty" bson:"pid_set,omitempty"`
	ConnInfo        string `json:"connect_info,omitempty" bson:"connect_info,omitempty"`
	Md5Hash         string `json:"md5_hash,omitempty" bson:"md5_hash,omitempty"`
	FileType        string `json:"class,omitempty" bson:"class,omitempty"`
	Name            string `json:"name,omitempty" bson:"name,omitempty"`
	ProcessNs       string `json:"pns,omitempty" bson:"pns,omitempty"`
	StaticFile      string `json:"static_file,omitempty" bson:"static_file,omitempty"`
}

type AlarmDbBaseData struct {
	AgentId         string `json:"agent_id" bson:"agent_id"`
	HostName        string `json:"hostname" bson:"hostname"`
	DataType        string `json:"data_type" bson:"data_type"`
	InIpv4List      string `json:"in_ipv4_list" bson:"in_ipv4_list"`
	ExIpv4List      string `json:"ex_ipv4_list" bson:"ex_ipv4_list"`
	Pid             string `json:"pid" bson:"pid"`
	Exec            string `json:"exe" bson:"exe"`
	Argv            string `json:"argv" bson:"argv"`
	Ppid            string `json:"ppid" bson:"ppid"`
	PpidArgv        string `json:"ppid_argv" bson:"ppid_argv"`
	Pgid            string `json:"pgid" bson:"pgid"`
	PgidArgv        string `json:"pgid_argv" bson:"pgid_argv"`
	UserName        string `json:"username" bson:"username"`
	PidTree         string `json:"pid_tree" bson:"pid_tree"`
	SocketPid       string `json:"socket_pid" bson:"socket_pid"`
	SocketArgv      string `json:"socket_argv" bson:"socket_argv"`
	SshInfo         string `json:"ssh_info" bson:"ssh_info"`
	Ssh             string `json:"ssh" bson:"ssh"`
	Uid             string `json:"uid" bson:"uid"`
	Dip             string `json:"dip" bson:"dip"`
	Dport           string `json:"dport" bson:"dport"`
	Sip             string `json:"sip" bson:"sip"`
	Sport           string `json:"sport" bson:"sport"`
	TargeId         string `json:"target_pid" bson:"target_pid"`
	PtraceRequest   string `json:"ptrace_request" bson:"ptrace_request"`
	Query           string `json:"query" bson:"query"`
	FilePath        string `json:"file_path" bson:"file_path"`
	ModInfo         string `json:"mod_info" bson:"mod_info"`
	KoFile          string `json:"ko_file" bson:"ko_file"`
	ModuleName      string `json:"module_name" bson:"module_name"`
	SyscallNumber   string `json:"syscall_number" bson:"syscall_number"`
	InterruptNumber string `json:"interrupt_number" bson:"interrupt_number"`
	Path            string `json:"path" bson:"path"`
	Types           string `json:"types" bson:"types"`
	User            string `json:"user" bson:"user"`
	OldUid          string `json:"old_uid,omitempty" bson:"old_uid,omitempty"`
	OldUserName     string `json:"old_username,omitempty" bson:"old_username,omitempty"`
	TopChain        string `json:"top_chain,omitempty" bson:"top_chain,omitempty"`
	TopRuleChain    string `json:"top_rule_chain,omitempty" bson:"top_rule_chain,omitempty"`
	TopRuleChainUs  string `json:"top_rule_chain_us,omitempty" bson:"top_rule_chain_us,omitempty"`
	AlertType       string `json:"alert_type,omitempty" bson:"alert_type,omitempty"`
	AlertTypeUs     string `json:"alert_type_us,omitempty" bson:"alert_type_us,omitempty"`
	Suggestion      string `json:"suggestion,omitempty" bson:"suggestion,omitempty"`
	ExtConns        string `json:"external_conns,omitempty" bson:"external_conns,omitempty"`
	InDocker        string `json:"docker,omitempty" bson:"docker,omitempty"`
	TimeStamp       string `json:"timestamp,omitempty" bson:"timestamp,omitempty"`
	ExeHash         string `json:"exe_hash,omitempty" bson:"exe_hash,omitempty"`
	CreateTime      string `json:"create_at,omitempty" bson:"create_at,omitempty"`
	ModifyTime      string `json:"modify_at,omitempty" bson:"modify_at,omitempty"`
	PidSet          string `json:"pid_set,omitempty" bson:"pid_set,omitempty"`
	ConnInfo        string `json:"connect_info,omitempty" bson:"connect_info,omitempty"`
	Md5Hash         string `json:"md5_hash,omitempty" bson:"md5_hash,omitempty"`
	FileType        string `json:"class,omitempty" bson:"class,omitempty"`
	Name            string `json:"name,omitempty" bson:"name,omitempty"`
	AttackId        string `json:"attack_id,omitempty" bson:"attack_id,omitempty"`
	KcAttackIdList  string `json:"attack_id_list,omitempty" bson:"attack_id_list,omitempty"`
	TraceId         string `json:"trace_id,omitempty" bson:"trace_id,omitempty"`
	ProcessNs       string `json:"pns,omitempty" bson:"pns,omitempty"`
	BfSrcList       string `json:"src_list,omitempty" bson:"src_list,omitempty"`
	BfDstList       string `json:"dst_list,omitempty" bson:"dst_list,omitempty"`
	EventId         string `json:"event_id,omitempty" bson:"event_id,omitempty"`
	EventName       string `json:"event_name,omitempty" bson:"event_name,omitempty"`
	ReasonSid       string `json:"reason_sid,omitempty" bson:"reason_sid,omitempty"`
	ReasonIp        string `json:"reason_ip,omitempty" bson:"reason_ip,omitempty"`
	ReasonFile      string `json:"reason_file,omitempty" bson:"reason_file,omitempty"`
	ReasonSidList   string `json:"reason_sid_list,omitempty" bson:"reason_sid_list,omitempty"`
	ReasonIpList    string `json:"reason_ip_list,omitempty" bson:"reason_ip_list,omitempty"`
	ReasonFileList  string `json:"reason_file_list,omitempty" bson:"reason_file_list,omitempty"`
	InIpv6List      string `json:"in_ipv6_list,omitempty" bson:"in_ipv6_list,omitempty"`
	ExIpv6List      string `json:"ex_ipv6_list,omitempty" bson:"ex_ipv6_list,omitempty"`
	LdPreload       string `json:"ld_preload,omitempty" bson:"ld_preload,omitempty"`
	RunPath         string `json:"run_path,omitempty" bson:"run_path"`
	Comm            string `json:"comm,omitempty" bson:"comm,omitempty"`
	Stdin           string `json:"stdin,omitempty" bson:"stdin,omitempty"`
	Stdout          string `json:"stdout,omitempty" bson:"stdout,omitempty"`
	StaticFile      string `json:"static_file,omitempty" bson:"static_file,omitempty"`
	OldName         string `json:"old_name,omitempty" bson:"old_name,omitempty"`
	NewName         string `json:"new_name,omitempty" bson:"new_name,omitempty"`
	FdName          string `json:"fd_name,omitempty" bson:"fd_name,omitempty"`
	Flags           string `json:"flags,omitempty" bson:"flags,omitempty"`
	TargetArgv      string `json:"target_argv,omitempty" bson:"target_argv,omitempty"`
	DataTypeStr     string `json:"data_type_str,omitempty" bson:"data_type_str,omitempty"`
	AlarmId         string `json:"alarm_id,omitempty" bson:"alarm_id,omitempty"`
}

type AlarmDbHandleData struct {
	Status      int    `json:"__alarm_status" bson:"__alarm_status"`
	UpdateTime  int64  `json:"__update_time" bson:"__update_time"`
	InsertTime  int64  `json:"__insert_time" bson:"__insert_time"`
	HandlerUser string `json:"__handler_user" bson:"__handler_user"`
	ErrorReason string `json:"__error_reason" bson:"__error_reason"`
}

type AlarmDbData struct {
	Id                string       `json:"_id" bson:"_id"`
	Info              HubAlarmInfo `json:"SMITH_ALERT_DATA" bson:"SMITH_ALERT_DATA"`
	AlarmDbBaseData   `json:",inline" bson:",inline"`
	AlarmDbHandleData `json:",inline" bson:",inline"`
}

type AlarmLangeHeader struct {
	Langage string `header:"Accept-Language"`
}

type AlarmHostInfo struct {
	HostName    string   `json:"hostname" bson:"hostname"`
	InnerIpList []string `json:"inner_ip_list" bson:"inner_ip_list"`
	OuterIpList []string `json:"outer_ip_list" bson:"outer_ip_list"`
	AgentId     string   `json:"agent_id" bson:"agent_id"`
}

type AlarmAttribution struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AlarmNodeDetailData struct {
	DataType      string                   `json:"data_type"`
	CommAlarm     AlarmDetailDataCommAlarm `json:"comm_alarm_info"`
	ContainerInfo AlarmDataContainerInfo   `json:"container_info"`
	Plus42        *AlarmDataType42         `json:"plus_alarm_info_42,omitempty"`
	Plus49        *AlarmDataType49         `json:"plus_alarm_info_49,omitempty"`
	Plus59        *AlarmDataType59         `json:"plus_alarm_info_59,omitempty"`
	Plus101       *AlarmDataType101        `json:"plus_alarm_info_101,omitempty"`
	Plus601       *AlarmDataType601        `json:"plus_alarm_info_601,omitempty"`
	Plus602       *AlarmDataType602        `json:"plus_alarm_info_602,omitempty"`
	Plus603       *AlarmDataType603        `json:"plus_alarm_info_603,omitempty"`
	Plus604       *AlarmDataType604        `json:"plus_alarm_info_604,omitempty"`
	Plus700       *AlarmDataType700        `json:"plus_alarm_info_700,omitempty"`
	Plus701       *AlarmDataType701        `json:"plus_alarm_info_701,omitempty"`
	Plus702       *AlarmDataType702        `json:"plus_alarm_info_702,omitempty"`
	Plus703       *AlarmDataType703        `json:"plus_alarm_info_703,omitempty"`
	Plus3004      *AlarmDataType3004       `json:"plus_alarm_info_3004,omitempty"`
	Plus4000      *AlarmDataType4000       `json:"plus_alarm_info_4000,omitempty"`
	Plus6001      *AlarmDataType6001       `json:"plus_alarm_info_6001,omitempty"`
	Plus6002      *AlarmDataType6002       `json:"plus_alarm_info_6002,omitempty"`
	Plus6003      *AlarmDataType6003       `json:"plus_alarm_info_6003,omitempty"`
}

type AlarmDetailData struct {
	DataType      string                   `json:"data_type"`
	DataTypeStr   string                   `json:"data_type_str"`
	BaseAgent     AlarmDetailDataBaseAgent `json:"base_info"`
	BaseAlarm     AlarmDetailDataBaseAlarm `json:"base_alarm_info"`
	CommAlarm     AlarmDetailDataCommAlarm `json:"comm_alarm_info"`
	ContainerInfo AlarmDataContainerInfo   `json:"container_info"`
	PlusKC        *AlarmKillChain          `json:"plus_kill_chain,omitempty"`
	Plus42        *AlarmDataType42         `json:"plus_alarm_info_42,omitempty"`
	Plus49        *AlarmDataType49         `json:"plus_alarm_info_49,omitempty"`
	Plus59        *AlarmDataType59         `json:"plus_alarm_info_59,omitempty"`
	Plus82        *AlarmDataType82         `json:"plus_alarm_info_82,omitempty"`
	Plus86        *AlarmDataType86         `json:"plus_alarm_info_86,omitempty"`
	Plus101       *AlarmDataType101        `json:"plus_alarm_info_101,omitempty"`
	Plus356       *AlarmDataType356        `json:"plus_alarm_info_356,omitempty"`
	Plus601       *AlarmDataType601        `json:"plus_alarm_info_601,omitempty"`
	Plus602       *AlarmDataType602        `json:"plus_alarm_info_602,omitempty"`
	Plus603       *AlarmDataType603        `json:"plus_alarm_info_603,omitempty"`
	Plus604       *AlarmDataType604        `json:"plus_alarm_info_604,omitempty"`
	Plus700       *AlarmDataType700        `json:"plus_alarm_info_700,omitempty"`
	Plus701       *AlarmDataType701        `json:"plus_alarm_info_701,omitempty"`
	Plus702       *AlarmDataType702        `json:"plus_alarm_info_702,omitempty"`
	Plus703       *AlarmDataType703        `json:"plus_alarm_info_703,omitempty"`
	Plus3004      *AlarmDataType3004       `json:"plus_alarm_info_3004,omitempty"`
	Plus4000      *AlarmDataType4000       `json:"plus_alarm_info_4000,omitempty"`
	Plus6001      *AlarmDataType6001       `json:"plus_alarm_info_6001,omitempty"`
	Plus6002      *AlarmDataType6002       `json:"plus_alarm_info_6002,omitempty"`
	Plus6003      *AlarmDataType6003       `json:"plus_alarm_info_6003,omitempty"`
	Endpoint      string                   `json:"endpoint,omitempty"`
}

type KillChainNodeDbData struct {
	Id                string             `json:"_id" bson:"_id"`
	AlertType         string             `json:"alert_type,omitempty" bson:"alert_type,omitempty"`
	AlertTypeUs       string             `json:"alert_type_us,omitempty" bson:"alert_type_us,omitempty"`
	Suggestion        string             `json:"suggestion,omitempty" bson:"suggestion,omitempty"`
	Info              HubAlarmInfo       `json:"SMITH_ALERT_DATA" bson:"SMITH_ALERT_DATA"`
	NodeList          []*AlarmDbBaseData `json:"node_list,omitempty" bson:"node_list,omitempty"`
	AlarmDbHandleData `json:",inline" bson:",inline"`
}

type AlarmRawData struct {
	RawData map[string]interface{} `json:"rawdata"`
}

type AlarmDetailDataCommAlarm struct {
	Pid       string `json:"pid"`
	Exec      string `json:"exec"`
	Argv      string `json:"argv"`
	Ppid      string `json:"ppid"`
	Ppid_argv string `json:"ppid_argv"`
	Pgid      string `json:"pgid"`
	Pgid_argv string `json:"pgid_argv"`
	Username  string `json:"username"`
}

type AlarmDataContainerInfo struct {
	ContainerName  string `json:"container_name"`
	ContainerImage string `json:"container_image"`
}

type AlarmDataType59 struct {
	PidTree    string `json:"pid_tree"`
	SocketPid  string `json:"socket_pid"`
	SocketArgv string `json:"socket_argv"`
	SshInfo    string `json:"ssh_info"`
	Ssh        string `json:"ssh"`
	Uid        string `json:"uid"`
	LdPreload  string `json:"ld_preload"`
	RunPath    string `json:"run_path"`
	Comm       string `json:"comm"`
	Stdin      string `json:"stdin"`
	Stdout     string `json:"stdout"`
}

type AlarmDataType49 struct {
	PidTree string `json:"pid_tree"`
	Sport   string `json:"sport"`
	Sip     string `json:"sip"`
}

type AlarmDataType42 struct {
	SshInfo string `json:"ssh_info"`
	PidTree string `json:"pid_tree"`
}

type AlarmDataType82 struct {
	PidTree string `json:"pid_tree"`
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

type AlarmDataType86 struct {
	PidTree string `json:"pid_tree"`
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

type AlarmDataType101 struct {
	TargeId       string `json:"target_pid"`
	PtraceRequest string `json:"ptrace_request"`
	TargetArgv    string `json:"target_argv"`
}

type AlarmDataType356 struct {
	FdName string `json:"fd_name"`
	Flags  string `json:"flags"`
}

type AlarmDataType5003 struct {
	Command string `json:"command"`
	Path    string `json:"path"`
	User    string `json:"user"`
}

type AlarmDataType601 struct {
	Query   string `json:"query"`
	PidTree string `json:"pid_tree"`
}

type AlarmDataType602 struct {
	FilePath string `json:"file_path"`
	ConnInfo string `json:"connect_info"`
	PidTree  string `json:"pid_tree"`
	SockArgv string `json:"socket_argv"`
}

type AlarmDataType603 struct {
	KoFile string `json:"ko_file"`
}

type AlarmDataType604 struct {
	OldUid      string `json:"old_uid"`
	PidTree     string `json:"pid_tree"`
	OldUserName string `json:"old_username"`
}

type AlarmDataType700 struct {
	ModuleName string `json:"module_name"`
}

type AlarmDataType701 struct {
	ModuleName    string `json:"module_name"`
	SyscallNumber string `json:"syscall_number"`
}

type AlarmDataType702 struct {
	ModuleName string `json:"module_name"`
}

type AlarmDataType703 struct {
	ModuleName      string `json:"module_name"`
	InterruptNumber string `json:"interrupt_number"`
}

type AlarmDataType3004 struct {
	Path string `json:"path"`
}

type AlarmDataType4000 struct {
	Sip   string `json:"sip"`
	Sport string `json:"sport"`
	Types string `json:"types"`
	User  string `json:"user"`
}

type AlarmKillChain struct {
	TopChain     string   `json:"top_chain"`
	TopRuleChain []string `json:"top_rule_chain"`
	ExtConns     string   `json:"external_conns"`
	InDocker     string   `json:"docker"`
	TimeStamp    string   `json:"timestamp"`
	PidSet       string   `json:"pid_set"`
	Ssh          string   `json:"ssh"`
}

type HubKillChainGraph struct {
	SmithKey string `json:"smith_key" bson:"smith_key"`
}

type AlarmDataType6001 struct {
	StaticFile string `json:"static_file"`
	FileHash   string `json:"file_hash"`
	Class      string `json:"class"`
	Types      string `json:"types"`
	Name       string `json:"name"`
	CreateTime string `json:"create_at"`
	ModifyTime string `json:"modify_at"`
	TimeStamp  string `json:"timestamp"`
}
type AlarmDataType6002 struct {
	Argv       string `json:"argv"`
	Pid        string `json:"pid"`
	StaticFile string `json:"static_file"`
	FileHash   string `json:"file_hash"`
	Ppid       string `json:"ppid"`
	Pgid       string `json:"pgid"`
	Uid        string `json:"uid"`
	Class      string `json:"class"`
	Types      string `json:"types"`
	Name       string `json:"name"`
	CreateTime string `json:"create_at"`
	ModifyTime string `json:"modify_at"`
	TimeStamp  string `json:"timestamp"`
}

type AlarmDataType6003 struct {
	StaticFile string `json:"static_file"`
	FileHash   string `json:"file_hash"`
	Class      string `json:"class"`
	Name       string `json:"name"`
	Types      string `json:"types"`
	CreateTime string `json:"create_at"`
	ModifyTime string `json:"modify_at"`
	TimeStamp  string `json:"timestamp"`
}

type AgentContainerInfo struct {
	Name  string `json:"name,omitempty" bson:"name,omitempty"`
	Image string `json:"image_name,omitempty" bson:"image_name,omitempty"`
}

// ****************************** Alarm summary data struct ******************************
type AlarmExtendInfoProcMatchKey struct {
	AgentId string `json:"agent_id"`
	Pid     string `json:"pid"`
}

type AlarmExtendVulInfo struct {
	AgentId string `json:"agent_id" bson:"agent_id"`
	Pid     string `json:"pid" bson:"pid"`
	CVE     string `json:"cve" bson:"cve"`
	TitleCN string `json:"title_cn" bson:"title_cn"`
}

type AlarmExtendListenPortInfo struct {
	AgentId    string `json:"agent_id" bson:"agent_id"`
	Pid        string `json:"pid" bson:"pid"`
	ListenAddr string `json:"listen_addr" bson:"listen_addr"`
}

type AlarmExtendInfo struct {
	ListenAddrInfo []AlarmExtendListenPortInfo `json:"listen_ports,omitempty" bson:"listen_ports,omitempty"`
	VulInfo        []AlarmExtendVulInfo        `json:"vul_info,omitempty" bson:"vul_info,omitempty"`
}

type AlarmAssetHost struct {
	HostName       string   `json:"hostname,omitempty"`
	InnerIPs       []string `json:"in_ip_list,omitempty"`
	OuterIPs       []string `json:"out_ip_list,omitempty"`
	AgentId        string   `json:"agent_id,omitempty"`
	Os             string   `json:"os,omitempty"`
	OsPlatform     string   `json:"os_platform,omitempty"`
	ContainerName  *string  `json:"container_name,omitempty"`
	ContainerImage *string  `json:"container_image,omitempty"`
	Tags           []string `json:"tag_list,omitempty"`
}

type AlarmAssetInfo struct {
	Host    *AlarmAssetHost             `json:"host_info,omitempty"`
	Cluster *alarm.AlarmAssetKubeCluter `json:"cluster_info,omitempty"`
}

type AlarmSummaryContent struct {
	AuditLogAlarm     *alarm.AlarmKubeDataInfo  `json:"audit_log_alarm,omitempty"`
	AlarmNode         *alarm.AlarmHidsDataInfo  `json:"alarm_node,omitempty"`
	KillChainNodeList []alarm.AlarmHidsDataInfo `json:"kill_chain_node_list,omitempty"`
	KillChainStepList []string                  `json:"kill_chain_step_list,omitempty"`
	ExtendInfo        *AlarmExtendInfo          `json:"extend_info,omitempty"`
}

type AlarmSummaryInfoResponse struct {
	AssetInfo AlarmAssetInfo         `json:"asset_info,omitempty"`
	AlarmDesc alarm.AlarmDescription `json:"alarm_desc,omitempty"`
	Content   AlarmSummaryContent    `json:"alarm_content,omitempty"`
	RawData   map[string]interface{} `json:"raw_data,omitempty"`
}

type AlarmPrevAndNextRequest struct {
	AlarmId    string                  `json:"alarm_id"`
	Conditions *alarm.AlarmQueryFilter `json:"conditions,omitempty"`
}

type AlarmPrevAndNextResponse struct {
	Prev *AlarmListItem `json:"prev,omitempty"`
	Next *AlarmListItem `json:"next,omitempty"`
}

type AlarmOneHandleFileOpt struct {
	FilePath string `json:"file_path"`
	Action   string `json:"action"`
}
