package v6

const (
	ALARM_DATA_TYPE_KC   string = ""
	ALARM_DATA_TYPE_42   string = "42"
	ALARM_DATA_TYPE_49   string = "49"
	ALARM_DATA_TYPE_59   string = "59"
	ALARM_DATA_TYPE_101  string = "101"
	ALARM_DATA_TYPE_601  string = "601"
	ALARM_DATA_TYPE_602  string = "602"
	ALARM_DATA_TYPE_603  string = "603"
	ALARM_DATA_TYPE_604  string = "604"
	ALARM_DATA_TYPE_700  string = "700"
	ALARM_DATA_TYPE_701  string = "701"
	ALARM_DATA_TYPE_702  string = "702"
	ALARM_DATA_TYPE_703  string = "703"
	ALARM_DATA_TYPE_3004 string = "3004"
	ALARM_DATA_TYPE_4000 string = "4000"
	ALARM_DATA_TYPE_6001 string = "6001"
	ALARM_DATA_TYPE_6002 string = "6002"
)

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

type AlarmDbData struct {
	Id              string       `json:"_id" bson:"_id"`
	AgentId         string       `json:"agent_id" bson:"agent_id"`
	HostName        string       `json:"hostname" bson:"hostname"`
	Info            HubAlarmInfo `json:"SMITH_ALERT_DATA" bson:"SMITH_ALERT_DATA"`
	Status          int          `json:"__alarm_status" bson:"__alarm_status"`
	DataType        string       `json:"data_type" bson:"data_type"`
	InIpv4List      string       `json:"in_ipv4_list" bson:"in_ipv4_list"`
	ExIpv4List      string       `json:"ex_ipv4_list" bson:"ex_ipv4_list"`
	UpdateTime      int64        `json:"__update_time" bson:"__update_time"`
	InsertTime      int64        `json:"__insert_time" bson:"__insert_time"`
	Pid             string       `json:"pid" bson:"pid"`
	Exec            string       `json:"exe" bson:"exe"`
	Argv            string       `json:"argv" bson:"argv"`
	Ppid            string       `json:"ppid" bson:"ppid"`
	PpidArgv        string       `json:"ppid_argv" bson:"ppid_argv"`
	Pgid            string       `json:"pgid" bson:"pgid"`
	PgidArgv        string       `json:"pgid_argv" bson:"pgid_argv"`
	UserName        string       `json:"username" bson:"username"`
	PidTree         string       `json:"pid_tree" bson:"pid_tree"`
	SocketPid       string       `json:"socket_pid" bson:"socket_pid"`
	SocketArgv      string       `json:"socket_argv" bson:"socket_argv"`
	SshInfo         string       `json:"ssh_info" bson:"ssh_info"`
	Ssh             string       `json:"ssh" bson:"ssh"`
	Uid             string       `json:"uid" bson:"uid"`
	Dip             string       `json:"dip" bson:"dip"`
	Dport           string       `json:"dport" bson:"dport"`
	Sip             string       `json:"sip" bson:"sip"`
	Sport           string       `json:"sport" bson:"sport"`
	TargeId         string       `json:"target_pid" bson:"target_pid"`
	PtraceRequest   string       `json:"ptrace_request" bson:"ptrace_request"`
	Query           string       `json:"query" bson:"query"`
	FilePath        string       `json:"file_path" bson:"file_path"`
	ModInfo         string       `json:"mod_info" bson:"mod_info"`
	ModuleName      string       `json:"module_name" bson:"module_name"`
	SyscallNumber   string       `json:"syscall_number" bson:"syscall_number"`
	InterruptNumber string       `json:"interrupt_number" bson:"interrupt_number"`
	Path            string       `json:"path" bson:"path"`
	Types           string       `json:"types" bson:"types"`
	User            string       `json:"user" bson:"user"`
	OldUid          string       `json:"old_uid" bson:"old_uid"`
	OldUserName     string       `json:"old_username" bson:"old_username"`
	TopChain        string       `json:"top_chain" bson:"top_chain"`
	TopRuleChain    string       `json:"top_rule_chain" bson:"top_rule_chain"`
	AlertType       string       `json:"alert_type" bson:"alert_type"`
	AlertTypeUs     string       `json:"alert_type_us" bson:"alert_type_us"`
	Suggestion      string       `json:"suggestion" bson:"suggestion"`
	Graph           string       `json:"graph" bson:"graph"`
	ExtConns        string       `json:"external_conns" bson:"external_conns"`
	InDocker        string       `json:"docker" bson:"docker"`
	TimeStamp       string       `json:"timestamp" bson:"timestamp"`
	ExeHash         string       `json:"exe_hash" bson:"exe_hash"`
	CreateTime      string       `json:"create_at" bson:"create_at"`
	ModifyTime      string       `json:"modify_at" bson:"modify_at"`
	PidSet          string       `json:"pid_set" bson:"pid_set"`
	ConnInfo        string       `json:"connect_info" bson:"connect_info"`
}

type AlarmDetailData struct {
	DataType  string                   `json:"data_type"`
	BaseAgent AlarmDetailDataBaseAgent `json:"base_info"`
	BaseAlarm AlarmDetailDataBaseAlarm `json:"base_alarm_info"`
	CommAlarm AlarmDetailDataCommAlarm `json:"comm_alarm_info"`
	PlusKC    AlarmKillChain           `json:"plus_kill_chain"`
	Plus42    AlarmDataType42          `json:"plus_alarm_info_42"`
	Plus49    AlarmDataType49          `json:"plus_alarm_info_49"`
	Plus59    AlarmDataType59          `json:"plus_alarm_info_59"`
	Plus101   AlarmDataType101         `json:"plus_alarm_info_101"`
	Plus601   AlarmDataType601         `json:"plus_alarm_info_601"`
	Plus602   AlarmDataType602         `json:"plus_alarm_info_602"`
	Plus603   AlarmDataType603         `json:"plus_alarm_info_603"`
	Plus604   AlarmDataType604         `json:"plus_alarm_info_604"`
	Plus700   AlarmDataType700         `json:"plus_alarm_info_700"`
	Plus701   AlarmDataType701         `json:"plus_alarm_info_701"`
	Plus702   AlarmDataType702         `json:"plus_alarm_info_702"`
	Plus703   AlarmDataType703         `json:"plus_alarm_info_703"`
	Plus3004  AlarmDataType3004        `json:"plus_alarm_info_3004"`
	Plus4000  AlarmDataType4000        `json:"plus_alarm_info_4000"`
	Plus6001  AlarmDataType6001        `json:"plus_alarm_info_6001"`
	Plus6002  AlarmDataType6002        `json:"plus_alarm_info_6002"`
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

type AlarmDataType59 struct {
	PidTree    string `json:"pid_tree"`
	SocketPid  string `json:"socket_pid"`
	SocketArgv string `json:"socket_argv"`
	SshInfo    string `json:"ssh_info"`
	Ssh        string `json:"ssh"`
	Uid        string `json:"uid"`
}

type AlarmDataType49 struct {
	PidTree string `json:"pid_tree"`
	Sport   string `json:"sport"`
}

type AlarmDataType42 struct {
	SshInfo string `json:"ssh_info"`
	PidTree string `json:"pid_tree"`
}

type AlarmDataType101 struct {
	TargeId       string `json:"target_pid"`
	PtraceRequest string `json:"ptrace_request"`
}

type AlarmDataType601 struct {
	Query string `json:"query"`
}

type AlarmDataType602 struct {
	FilePath string `json:"file_path"`
}

type AlarmDataType603 struct {
	ModInfo string `json:"mod_info"`
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
	TopChain     string `json:"top_chain"`
	TopRuleChain string `json:"top_rule_chain"`
	Graph        string `json:"graph"`
	ExtConns     string `json:"external_conns"`
	InDocker     string `json:"docker"`
	TimeStamp    string `json:"timestamp"`
	PidSet       string `json:"pid_set"`
	Ssh          string `json:"ssh"`
}

type AlarmDataType6001 struct {
	Exe        string `json:"exe"`
	ExeHash    string `json:"exe_hash"`
	Types      string `json:"types"`
	CreateTime string `json:"create_at"`
	ModifyTime string `json:"modify_at"`
	TimeStamp  string `json:"timestamp"`
}
type AlarmDataType6002 struct {
	Argv       string `json:"argv"`
	Pid        string `json:"pid"`
	Exe        string `json:"exe"`
	ExeHash    string `json:"exe_hash"`
	Ppid       string `json:"ppid"`
	Pgid       string `json:"pgid"`
	Uid        string `json:"uid"`
	Types      string `json:"types"`
	CreateTime string `json:"create_at"`
	ModifyTime string `json:"modify_at"`
	TimeStamp  string `json:"timestamp"`
}

func CopyDataTypeKC(dst *AlarmDetailData, src *AlarmDbData) {
	dst.PlusKC.TopChain = src.TopChain
	dst.PlusKC.TopRuleChain = src.TopRuleChain
	dst.PlusKC.ExtConns = src.ExtConns
	dst.PlusKC.Graph = src.Graph
	dst.PlusKC.InDocker = src.InDocker
	dst.PlusKC.TimeStamp = src.TimeStamp
	dst.PlusKC.PidSet = src.PidSet
	dst.PlusKC.Ssh = src.Ssh
}

func CopyDataType6001(dst *AlarmDetailData, src *AlarmDbData) {
	dst.Plus6001.Exe = src.Exec
	dst.Plus6001.ExeHash = src.ExeHash
	dst.Plus6001.Types = src.Types
	dst.Plus6001.CreateTime = src.CreateTime
	dst.Plus6001.ModifyTime = src.ModifyTime
	dst.Plus6001.TimeStamp = src.TimeStamp
}

func CopyDataType6002(dst *AlarmDetailData, src *AlarmDbData) {
	dst.Plus6002.Argv = src.Argv
	dst.Plus6002.CreateTime = src.CreateTime
	dst.Plus6002.Exe = src.Exec
	dst.Plus6002.ExeHash = src.ExeHash
	dst.Plus6002.ModifyTime = src.ModifyTime
	dst.Plus6002.Pgid = src.Pgid
	dst.Plus6002.Pid = src.Pid
	dst.Plus6002.Ppid = src.Ppid
	dst.Plus6002.TimeStamp = src.TimeStamp
	dst.Plus6002.Types = src.Types
	dst.Plus6002.Uid = src.Uid
}
