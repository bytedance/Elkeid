package v6

type RaspAlarmDbBaseData struct {
	AgentId          string   `json:"agent_id" bson:"agent_id"`
	HostName         string   `json:"hostname" bson:"hostname"`
	DataType         string   `json:"data_type" bson:"data_type"`
	InIpv4List       string   `json:"in_ipv4_list" bson:"in_ipv4_list"`
	ExIpv4List       string   `json:"ex_ipv4_list" bson:"ex_ipv4_list"`
	InIpv6List       string   `json:"in_ipv6_list,omitempty" bson:"in_ipv6_list,omitempty"`
	ExIpv6List       string   `json:"ex_ipv6_list,omitempty" bson:"ex_ipv6_list,omitempty"`
	Suggestion       string   `json:"suggestion,omitempty" bson:"suggestion,omitempty"`
	AlertType        string   `json:"alert_type,omitempty" bson:"alert_type,omitempty"`
	AlertTypeUs      string   `json:"alert_type_us,omitempty" bson:"alert_type_us,omitempty"`
	AttackId         string   `json:"attack_id,omitempty" bson:"attack_id,omitempty"`
	KcAttackIdList   string   `json:"attack_id_list,omitempty" bson:"attack_id_list,omitempty"`
	ArgsList         []string `json:"args_array,omitempty" bson:"args_array,omitempty"`
	Pid              string   `json:"pid,omitempty" bson:"pid,omitempty"`
	NsPid            string   `json:"nspid,omitempty" bson:"nspid,omitempty"`
	Sid              string   `json:"sid,omitempty" bson:"sid,omitempty"`
	ProbeHook        string   `json:"probe_hook,omitempty" bson:"probe_hook,omitempty"`
	StackTraceFormat string   `json:"stack_trace_format,omitempty" bson:"stack_trace_format,omitempty"`
	StackTraceHash   string   `json:"stack_trace_hash,omitempty" bson:"stack_trace_hash,omitempty"`
	TraceId          string   `json:"trace_id,omitempty" bson:"trace_id,omitempty"`
	EventId          string   `json:"event_id,omitempty" bson:"event_id,omitempty"`
	EventName        string   `json:"event_name,omitempty" bson:"event_name,omitempty"`
	InDocker         string   `json:"in_container,omitempty" bson:"in_container,omitempty"`
}

type RaspAlarmDbData struct {
	Id                  string       `json:"_id" bson:"_id"`
	Info                HubAlarmInfo `json:",inline" bson:",inline"`
	RuleName            string       `json:"rule_name" bson:"rule_name"`
	HarmLevel           string       `json:"HarmLevel" bson:"HarmLevel"`
	Desc                string       `json:"Desc" bson:"Desc"`
	AlarmDbHandleData   `json:",inline" bson:",inline"`
	RaspAlarmDbBaseData `json:",inline" bson:",inline"`
}

type RaspAlarmQueryFilter struct {
	Name        string   `json:"name" bson:"name"`
	StatusList  []int    `json:"status" bson:"status"`
	Hostname    string   `json:"hostname" bson:"hostname"`
	Ip          string   `json:"ip" bson:"ip"`
	TypeList    []string `json:"type" bson:"type"`
	LevelList   []string `json:"level" bson:"level"`
	StartTime   int64    `json:"time_start" bson:"time_start"`
	EndTime     int64    `json:"time_end" bson:"time_end"`
	AgentId     string   `json:"agent_id" bson:"agent_id"`
	EventName   string   `json:"event_name" bson:"event_name"`
	EventId     string   `json:"event_id" bson:"event_id"`
	EventReason string   `json:"event_reason" bson:"event_reason"`
}

type RaspAlarmRawDataItem struct {
	RawData map[string]interface{} `json:"rawdata"`
}

type RaspAlarmExportDataRequest struct {
	AlarmIdList *[]string             `json:"alarm_id_list"`
	Conditions  *RaspAlarmQueryFilter `json:"conditions"`
}

type RaspAlarmListRequest struct {
	Name        string   `json:"name,omitempty"`
	Status      []int    `json:"status,omitempty"`
	LevelList   []string `json:"level,omitempty"`
	TypeList    []string `json:"type,omitempty"`
	DataType    string   `json:"data_type,omitempty"`
	TimeStart   int64    `json:"time_start,omitempty"`
	TimeEnd     int64    `json:"time_end,omitempty"`
	AgentId     string   `json:"agent_id,omitempty"`
	EventId     string   `json:"event_id,omitempty"`
	EventName   string   `json:"event_name,omitempty"`
	EventReason string   `json:"event_reason,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Ip          string   `json:"ip,omitempty"`
}

type RaspAlarmListItem struct {
	AlarmId     string             `json:"alarm_id"`
	AgentId     string             `json:"agent_id"`
	Status      int                `json:"status"`
	Type        string             `json:"type"`
	Name        string             `json:"name"`
	Level       string             `json:"level"`
	HostName    string             `json:"alarm_hostname"`
	AlarmTime   int64              `json:"alarm_time"`
	TraceId     string             `json:"trace_id"`
	EventId     string             `json:"event_id"`
	EventName   string             `json:"event_name"`
	Attribution []AlarmAttribution `json:"attribution_list"`
	Host        AlarmHostInfo      `json:"host"`
	DataType    string             `json:"data_type"`
	ErrReason   string             `json:"error_reason,omitempty"`
}

type RaspAlarmStatusUpdateRequest struct {
	AlarmIdList *[]string             `json:"alarm_id_list"`
	Conditions  *RaspAlarmQueryFilter `json:"conditions"`
	NewStatus   int                   `json:"status"`
}

type RaspAlarmStatusUpdateItem struct {
	AlarmId string `json:"alarm_id"`
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
}

type RaspAlarmStatisticsRequest struct {
	AgentId string `form:"agent_id"`
}

type RaspAlarmStatistics struct {
	Total            int `json:"alarm_total"`
	CriticalLevelNum int `json:"alarm_critical_num"`
	HighLevelNum     int `json:"alarm_high_num"`
	MediumLevelNum   int `json:"alarm_medium_num"`
	LowLevelNum      int `json:"alarm_low_num"`
	ProcessedNum     int `json:"alarm_processed_num"`
	WhiteListNum     int `json:"alarm_white_num"`
}

type AlarmDataType2439 struct {
	Args           []string `json:"args,omitempty"`
	Pid            string   `json:"pid,omitempty"`
	NsPid          string   `json:"nspid,omitempty"`
	ProbeHook      string   `json:"probe_hook,omitempty"`
	StackTrace     string   `json:"stack_trace,omitempty"`
	StackTraceHash string   `json:"stack_trace_hash,omitempty"`
}

type RaspAlarmDataBaseInfo struct {
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

type RaspAlarmAbstractData struct {
	DataType      string                   `json:"data_type"`
	BaseAgent     AlarmDetailDataBaseAgent `json:"base_info"`
	BaseAlarm     RaspAlarmDataBaseInfo    `json:"base_alarm_info"`
	ContainerInfo AlarmDataContainerInfo   `json:"container_info"`
	Plus2439      *AlarmDataType2439       `json:"plus_alarm_info_2439,omitempty"`
}
