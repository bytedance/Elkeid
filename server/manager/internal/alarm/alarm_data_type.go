package alarm

type AlarmDailyStatInfo struct {
	DayTime     int64 `json:"daytime" bson:"daytime"`
	UnhandleNum int64 `json:"unhandle_count" bson:"unhandle_count"`
	UpdateTime  int64 `json:"update_time,omitempty" bson:"update_time,omitempty"`
}

type AlarmHidsHostInfo struct {
	AgentId    *string `json:"agent_id,omitempty" bson:"agent_id,omitempty"`
	HostName   *string `json:"hostname,omitempty" bson:"hostname,omitempty"`
	InIpv4List *string `json:"in_ipv4_list,omitempty" bson:"in_ipv4_list,omitempty"`
	ExIpv4List *string `json:"ex_ipv4_list,omitempty" bson:"ex_ipv4_list,omitempty"`
	InIpv6List *string `json:"in_ipv6_list,omitempty" bson:"in_ipv6_list,omitempty"`
	ExIpv6List *string `json:"ex_ipv6_list,omitempty" bson:"ex_ipv6_list,omitempty"`
}

type AlarmAssetKubeCluter struct {
	ClusterId   *string `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterName *string `json:"cluster_name,omitempty" bson:"cluster,omitempty"`
	ClusterArea *string `json:"cluster_area,omitempty" bson:"cluster_area,omitempty"`
}

type AlarmEventInfo struct {
	EventId        *string `json:"event_id,omitempty" bson:"event_id,omitempty"`
	EventName      *string `json:"event_name,omitempty" bson:"event_name,omitempty"`
	ReasonSid      *string `json:"reason_sid,omitempty" bson:"reason_sid,omitempty"`
	ReasonIp       *string `json:"reason_ip,omitempty" bson:"reason_ip,omitempty"`
	ReasonFile     *string `json:"reason_file,omitempty" bson:"reason_file,omitempty"`
	ReasonSidList  *string `json:"reason_sid_list,omitempty" bson:"reason_sid_list,omitempty"`
	ReasonIpList   *string `json:"reason_ip_list,omitempty" bson:"reason_ip_list,omitempty"`
	ReasonFileList *string `json:"reason_file_list,omitempty" bson:"reason_file_list,omitempty"`
}

type AlarmDescription struct {
	// common
	AlertType      string  `json:"alert_type,omitempty" bson:"alert_type,omitempty"`
	AlertTypeUs    string  `json:"alert_type_us,omitempty" bson:"alert_type_us,omitempty"`
	Status         int     `json:"status" bson:"__alarm_status"`
	InsertTime     int64   `json:"insert_time" bson:"__insert_time"`
	Suggestion     string  `json:"suggestion,omitempty" bson:"suggestion,omitempty"`
	AttackId       *string `json:"attack_id,omitempty" bson:"attack_id,omitempty"`
	KcAttackIdList *string `json:"attack_id_list,omitempty" bson:"attack_id_list,omitempty"`
	HandlerUser    *string `json:"handle_user,omitempty" bson:"__handler_user,omitempty"`
	HandlerTime    int64   `json:"handle_time,omitempty" bson:"__update_time,omitempty"`
	InDocker       *string `json:"docker,omitempty" bson:"docker,omitempty"`
	RuleName       *string `json:"rule_name,omitempty" bson:"rule_name,omitempty"`
	Desc           *string `json:"desc,omitempty" bson:"desc,omitempty"`
	AlarmId        *string `json:"alarm_id,omitempty" bson:"alarm_id,omitempty"`
	AlarmDetail    *string `json:"alert_detail,omitempty" bson:"alert_detail,omitempty"`
	TraceId        *string `json:"trace_id,omitempty" bson:"trace_id,omitempty"`
	ErrorReason    *string `json:"error_reason" bson:"__error_reason"`

	// hids special
	DataTypeStr    *string `json:"data_type_str,omitempty" bson:"data_type_str,omitempty"`
	HidsAlarmLevel *string `json:"hids_level,omitempty" bson:"harm_level,omitempty"`

	// rasp special
	RaspAlarmLevel *string `json:"rasp_level,omitempty" bson:"HarmLevel,omitempty"`

	// kube special
	KubeAlarmLevel *string `json:"kube_level,omitempty" bson:"level,omitempty"`
	AlertDesc      *string `json:"alert_desc,omitempty" bson:"alert_desc,omitempty"`
	RiskDesc       *string `json:"risk_desc,omitempty" bson:"risk_desc,omitempty"`
}

type AlarmSecondaryDataInfo struct {
	ProcessNs *string `json:"pns,omitempty" bson:"pns,omitempty"`
	// killchain specail
	TopChain       *string `json:"top_chain,omitempty" bson:"top_chain,omitempty"`
	TopRuleChain   *string `json:"top_rule_chain,omitempty" bson:"top_rule_chain,omitempty"`
	TopRuleChainUs *string `json:"top_rule_chain_us,omitempty" bson:"top_rule_chain_us,omitempty"`
}

type AlarmHidsDataInfo struct {
	// data type
	DataType string `json:"data_type,omitempty" bson:"data_type,omitempty"`
	// process info
	PidTree  *string `json:"pid_tree,omitempty" bson:"pid_tree,omitempty"`
	Pid      *string `json:"pid,omitempty" bson:"pid,omitempty"`
	Exec     *string `json:"exe,omitempty" bson:"exe,omitempty"`
	Argv     *string `json:"argv,omitempty" bson:"argv,omitempty"`
	Ppid     *string `json:"ppid,omitempty" bson:"ppid,omitempty"`
	PpidArgv *string `json:"ppid_argv,omitempty" bson:"ppid_argv,omitempty"`
	Pgid     *string `json:"pgid,omitempty" bson:"pgid,omitempty"`
	PgidArgv *string `json:"pgid_argv,omitempty" bson:"pgid_argv,omitempty"`
	// other data
	UserName        *string `json:"username,omitempty" bson:"username,omitempty"`
	SocketPid       *string `json:"socket_pid,omitempty" bson:"socket_pid,omitempty"`
	SocketArgv      *string `json:"socket_argv,omitempty" bson:"socket_argv,omitempty"`
	SshInfo         *string `json:"ssh_info,omitempty" bson:"ssh_info,omitempty"`
	Ssh             *string `json:"ssh,omitempty" bson:"ssh,omitempty"`
	Uid             *string `json:"uid,omitempty" bson:"uid,omitempty"`
	Dip             *string `json:"dip,omitempty" bson:"dip,omitempty"`
	Dport           *string `json:"dport,omitempty" bson:"dport,omitempty"`
	Sip             *string `json:"sip,omitempty" bson:"sip,omitempty"`
	Sport           *string `json:"sport,omitempty" bson:"sport,omitempty"`
	TargeId         *string `json:"target_pid,omitempty" bson:"target_pid,omitempty"`
	PtraceRequest   *string `json:"ptrace_request,omitempty" bson:"ptrace_request,omitempty"`
	Query           *string `json:"query,omitempty" bson:"query,omitempty"`
	FilePath        *string `json:"file_path,omitempty" bson:"file_path,omitempty"`
	ModInfo         *string `json:"mod_info,omitempty" bson:"mod_info,omitempty"`
	KoFile          *string `json:"ko_file,omitempty" bson:"ko_file,omitempty"`
	ModuleName      *string `json:"module_name,omitempty" bson:"module_name,omitempty"`
	SyscallNumber   *string `json:"syscall_number,omitempty" bson:"syscall_number,omitempty"`
	InterruptNumber *string `json:"interrupt_number,omitempty" bson:"interrupt_number,omitempty"`
	Path            *string `json:"path,omitempty" bson:"path,omitempty"`
	Types           *string `json:"types,omitempty" bson:"types,omitempty"`
	User            *string `json:"user,omitempty" bson:"user,omitempty"`
	OldUid          *string `json:"old_uid,omitempty" bson:"old_uid,omitempty"`
	OldUserName     *string `json:"old_username,omitempty" bson:"old_username,omitempty"`
	ExtConns        *string `json:"external_conns,omitempty" bson:"external_conns,omitempty"`
	TimeStamp       *string `json:"timestamp,omitempty" bson:"timestamp,omitempty"`
	ExeHash         *string `json:"exe_hash,omitempty" bson:"exe_hash,omitempty"`
	CreateTime      *string `json:"create_at,omitempty" bson:"create_at,omitempty"`
	ModifyTime      *string `json:"modify_at,omitempty" bson:"modify_at,omitempty"`
	PidSet          *string `json:"pid_set,omitempty" bson:"pid_set,omitempty"`
	ConnInfo        *string `json:"connect_info,omitempty" bson:"connect_info,omitempty"`
	Md5Hash         *string `json:"md5_hash,omitempty" bson:"md5_hash,omitempty"`
	FileType        *string `json:"class,omitempty" bson:"class,omitempty"`
	Name            *string `json:"name,omitempty" bson:"name,omitempty"`
	BfSrcList       *string `json:"src_list,omitempty" bson:"src_list,omitempty"`
	BfDstList       *string `json:"dst_list,omitempty" bson:"dst_list,omitempty"`
	LdPreload       *string `json:"ld_preload,omitempty" bson:"ld_preload,omitempty"`
	RunPath         *string `json:"run_path,omitempty" bson:"run_path"`
	Comm            *string `json:"comm,omitempty" bson:"comm,omitempty"`
	Stdin           *string `json:"stdin,omitempty" bson:"stdin,omitempty"`
	Stdout          *string `json:"stdout,omitempty" bson:"stdout,omitempty"`
	StaticFile      *string `json:"static_file,omitempty" bson:"static_file,omitempty"`
	OldName         *string `json:"old_name,omitempty" bson:"old_name,omitempty"`
	NewName         *string `json:"new_name,omitempty" bson:"new_name,omitempty"`
	FdName          *string `json:"fd_name,omitempty" bson:"fd_name,omitempty"`
	Flags           *string `json:"flags,omitempty" bson:"flags,omitempty"`
	TargetArgv      *string `json:"target_argv,omitempty" bson:"target_argv,omitempty"`
	// rasp special
	ArgsList         []string `json:"args_array,omitempty" bson:"args_array,omitempty"`
	NsPid            *string  `json:"nspid,omitempty" bson:"nspid,omitempty"`
	Sid              *string  `json:"sid,omitempty" bson:"sid,omitempty"`
	ProbeHook        *string  `json:"probe_hook,omitempty" bson:"probe_hook,omitempty"`
	StackTraceFormat *string  `json:"stack_trace_format,omitempty" bson:"stack_trace_format,omitempty"`
	StackTraceHash   *string  `json:"stack_trace_hash,omitempty" bson:"stack_trace_hash,omitempty"`
	// virus scan
	HitData     *string `json:"hit_data,omitempty" bson:"hit_data,omitempty"`
	IocSrc      *string `json:"ioc_source,omitempty" bson:"ioc_source,omitempty"`
	IocSeverity *string `json:"ioc_severity,omitempty" bson:"ioc_severity,omitempty"`
	IocMeta     *string `json:"ioc_meta,omitempty" bson:"ioc_meta,omitempty"`
	IocDetail   *string `json:"ioc_detail,omitempty" bson:"ioc_detail,omitempty"`
	// highlight fields
	HighlightFields *string `json:"highlight_fields,omitempty" bson:"highlight_fields,omitempty"`
}

type AlarmKubeDataInfo struct {
	SourceIP           *string  `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	SourceAsset        *string  `json:"source_ip_asset,omitempty" bson:"source_ip_asset,omitempty"`
	UserAgent          *string  `json:"user_agent,omitempty" bson:"user_agent,omitempty"`
	KubeUserName       *string  `json:"user_name,omitempty" bson:"user_name,omitempty"`
	KubeUserGroup      *string  `json:"user_groups,omitempty" bson:"user_groups,omitempty"`
	RealUserName       *string  `json:"real_user_name,omitempty" bson:"real_user_name,omitempty"`
	RealUserGroup      []string `json:"real_user_groups,omitempty" bson:"real_user_groups,omitempty"`
	ImpUserName        *string  `json:"impersonated_user_name,omitempty" bson:"impersonated_user_name,omitempty"`
	ImpUserGroup       *string  `json:"impersonated_user_groups,omitempty" bson:"impersonated_user_groups,omitempty"`
	Verb               *string  `json:"verb,omitempty" bson:"verb,omitempty"`
	ResNamespace       *string  `json:"resource_namespace,omitempty" bson:"resource_namespace,omitempty"`
	ResKind            *string  `json:"resource_kind,omitempty" bson:"resource_kind,omitempty"`
	ResName            *string  `json:"resource_name,omitempty" bson:"resource_name,omitempty"`
	RequestUri         *string  `json:"request_uri,omitempty" bson:"request_uri,omitempty"`
	ResponseCode       *string  `json:"response_code,omitempty" bson:"response_code,omitempty"`
	ResponseStatus     *string  `json:"response_status,omitempty" bson:"response_status,omitempty"`
	ResponseReason     *string  `json:"response_reason,omitempty" bson:"response_reason,omitempty"`
	ExecComd           *string  `json:"exec_command,omitempty" bson:"exec_command,omitempty"`
	ExecContainer      *string  `json:"exec_container,omitempty" bson:"exec_container,omitempty"`
	ImageList          []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset              *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
	PrivCap            []string `json:"privileged_capabilities,omitempty" bson:"privileged_capabilities,omitempty"`
	ShareNs            []string `json:"shared_namespaces,omitempty" bson:"shared_namespaces,omitempty"`
	ReadWriteMountList []string `json:"read_write_mounts,omitempty" bson:"read_write_mounts,omitempty"`
	ReadOnlyMountList  []string `json:"read_only_mounts,omitempty" bson:"read_only_mounts,omitempty"`
	BindRoleref        *string  `json:"binding_roleref,omitempty" bson:"binding_roleref,omitempty"`
	BindSubject        *string  `json:"binding_subject,omitempty" bson:"binding_subject,omitempty"`
	NodeName           *string  `json:"node_name,omitempty" bson:"node_name,omitempty"`
	NodeHost           *string  `json:"node_host,omitempty" bson:"node_host,omitempty"`
	Body               *string  `json:"body,omitempty" bson:"body,omitempty"`
}

type AlarmDbDataInfo struct {
	Id                     string `json:"id" bson:"_id"`
	AlarmDescription       `json:",inline" bson:",inline"`
	AlarmSecondaryDataInfo `json:",inline" bson:",inline"`

	// hids & rasp special
	AlarmHidsHostInfo `json:",inline" bson:",inline"`
	AlarmHidsDataInfo `json:",inline" bson:",inline"`

	// kube special
	AlarmAssetKubeCluter `json:",inline" bson:",inline"`
	AlarmKubeDataInfo    `json:",inline" bson:",inline"`

	// kill chain special
	KcNodeList []AlarmHidsDataInfo `json:"node_list,omitempty" bson:"node_list,omitempty"`

	// event info
	AlarmEventInfo `json:",inline" bson:",inline"`
}

type AlarmQueryFilter struct {
	Name          string   `json:"name,omitempty" bson:"name,omitempty"`
	StatusList    []int    `json:"status,omitempty" bson:"status,omitempty"`
	Hostname      string   `json:"hostname,omitempty" bson:"hostname,omitempty"`
	Ip            string   `json:"ip,omitempty" bson:"ip,omitempty"`
	TypeList      []string `json:"type,omitempty" bson:"type,omitempty"`
	LevelList     []string `json:"level,omitempty" bson:"level,omitempty"`
	StartTime     int64    `json:"time_start,omitempty" bson:"time_start,omitempty"`
	EndTime       int64    `json:"time_end,omitempty" bson:"time_end,omitempty"`
	AgentId       string   `json:"agent_id,omitempty" bson:"agent_id,omitempty"`
	EventName     string   `json:"event_name,omitempty" bson:"event_name,omitempty"`
	EventId       string   `json:"event_id,omitempty" bson:"event_id,omitempty"`
	EventReason   string   `json:"event_reason,omitempty" bson:"event_reason,omitempty"`
	FilePath      string   `json:"file_path,omitempty" bson:"file_path,omitempty"`
	FileHash      string   `json:"file_hash,omitempty" bson:"file_hash,omitempty"`
	ClusterId     string   `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterRegion string   `json:"cluster_region,omitempty" bson:"cluster_region,omitempty"`
	ClusterName   string   `json:"cluster_name,omitempty" bson:"cluster_name,omitempty"`
	TaskID        string   `json:"task_id,omitempty" bson:"task_id,omitempty"`
}

type AlarmStatusUpdateManyRequest struct {
	AlarmIdList *[]string         `json:"alarm_id_list"`
	Conditions  *AlarmQueryFilter `json:"conditions"`
	NewStatus   int               `json:"status"`
}
