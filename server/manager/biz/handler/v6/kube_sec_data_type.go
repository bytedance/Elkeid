package v6

import (
	"github.com/bytedance/Elkeid/server/manager/internal/kube"
)

// ************************************* ALARM *************************************
type KubeAuditLogDbBaseData struct {
	ClusterId      string `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty" bson:"cluster,omitempty"`
	ClusterArea    string `json:"cluster_area,omitempty" bson:"cluster_area,omitempty"`
	RuleName       string `json:"rule_name,omitempty" bson:"rule_name,omitempty"`
	AlertType      string `json:"alert_type_us,omitempty" bson:"alert_type_us,omitempty"`
	Level          string `json:"level,omitempty" bson:"level,omitempty"`
	AlertDesc      string `json:"alert_desc,omitempty" bson:"alert_desc,omitempty"`
	AttackIds      string `json:"attack_id,omitempty" bson:"attack_id,omitempty"`
	RuleTypeFirst  string `json:"rule_type_1st,omitempty" bson:"rule_type_1st,omitempty"`
	RuleTypeSecond string `json:"rule_type_2nd,omitempty" bson:"rule_type_2nd,omitempty"`
	RiskDesc       string `json:"risk_desc,omitempty" bson:"risk_desc,omitempty"`
	Suggestion     string `json:"suggestion,omitempty" bson:"suggestion,omitempty"`
	Status         int    `json:"__alarm_status,omitempty" bson:"__alarm_status,omitempty"`
	UpdateTime     int64  `json:"__update_time,omitempty" bson:"__update_time,omitempty"`
	CreateTime     int64  `json:"__insert_time,omitempty" bson:"__insert_time,omitempty"`
	HandlerUser    string `json:"__handler_user,omitempty" bson:"__handler_user,omitempty"`
	DataType       string `json:"data_type,omitempty" bson:"data_type,omitempty"`
}

type KubeAuditLogDbRiskData struct {
	SourceIP       string   `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	SourceAsset    string   `json:"source_ip_asset,omitempty" bson:"source_ip_asset,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty" bson:"user_agent,omitempty"`
	UserName       string   `json:"user_name,omitempty" bson:"user_name,omitempty"`
	UserGroup      string   `json:"user_groups,omitempty" bson:"user_groups,omitempty"`
	RealUserName   string   `json:"real_user_name,omitempty" bson:"real_user_name,omitempty"`
	RealUserGroup  []string `json:"real_user_groups,omitempty" bson:"real_user_groups,omitempty"`
	ImpUserName    string   `json:"impersonated_user_name,omitempty" bson:"impersonated_user_name,omitempty"`
	ImpUserGroup   string   `json:"impersonated_user_groups,omitempty" bson:"impersonated_user_groups,omitempty"`
	Verb           string   `json:"verb,omitempty" bson:"verb,omitempty"`
	ResNamespace   string   `json:"resource_namespace,omitempty" bson:"resource_namespace,omitempty"`
	ResKind        string   `json:"resource_kind,omitempty" bson:"resource_kind,omitempty"`
	ResName        string   `json:"resource_name,omitempty" bson:"resource_name,omitempty"`
	RequestUri     string   `json:"request_uri,omitempty" bson:"request_uri,omitempty"`
	ResponseCode   string   `json:"response_code,omitempty" bson:"response_code,omitempty"`
	ResponseStatus string   `json:"response_status,omitempty" bson:"response_status,omitempty"`
	ResponseReason string   `json:"response_reason,omitempty" bson:"response_reason,omitempty"`
}

type KubeAlarmDbData struct {
	AlarmId                string `json:"alarm_id,omitempty" bson:"_id,omitempty"`
	KubeAuditLogDbBaseData `json:",inline" bson:",inline"`
	KubeAuditLogDbRiskData `json:",inline" bson:",inline"`
	DataType               string   `json:"data_type" bson:"data_type"`
	ExecComd               string   `json:"exec_command,omitempty" bson:"exec_command,omitempty"`
	ExecContainer          string   `json:"exec_container,omitempty" bson:"exec_container,omitempty"`
	ImageList              []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset                  *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
	PrivCap                []string `json:"privileged_capabilities,omitempty" bson:"privileged_capabilities,omitempty"`
	ShareNs                []string `json:"shared_namespaces,omitempty" bson:"shared_namespaces,omitempty"`
	ReadWriteMountList     []string `json:"read_write_mounts,omitempty" bson:"read_write_mounts,omitempty"`
	ReadOnlyMountList      []string `json:"read_only_mounts,omitempty" bson:"read_only_mounts,omitempty"`
	BindRoleref            string   `json:"binding_roleref,omitempty" bson:"binding_roleref,omitempty"`
	BindSubject            string   `json:"binding_subject,omitempty" bson:"binding_subject,omitempty"`
}

type KubeAuditLogDataPlus9004 struct {
	ExecComd      string `json:"exec_command,omitempty" bson:"exec_command,omitempty"`
	ExecContainer string `json:"exec_container,omitempty" bson:"exec_container,omitempty"`
}

type KubeAuditLogDataPlus9005 struct {
	ImageList []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset     *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
}

type KubeAuditLogDataPlus9006 struct {
	ImageList []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset     *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
	PrivCap   []string `json:"privileged_capabilities,omitempty" bson:"privileged_capabilities,omitempty"`
}

type KubeAuditLogDataPlus9007 struct {
	ImageList []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset     *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
	ShareNs   []string `json:"shared_namespaces,omitempty" bson:"shared_namespaces,omitempty"`
}

type KubeAuditLogDataPlus9008 struct {
	ImageList          []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset              *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
	ReadWriteMountList []string `json:"read_write_mounts,omitempty" bson:"read_write_mounts,omitempty"`
}

type KubeAuditLogDataPlus9009 struct {
	ImageList         []string `json:"images,omitempty" bson:"images,omitempty"`
	Asset             *string  `json:"workload_asset,omitempty" bson:"workload_asset,omitempty"`
	ReadOnlyMountList []string `json:"read_only_mounts,omitempty" bson:"read_only_mounts,omitempty"`
}

type KubeAuditLogDataPlus9010 struct {
	BindRoleref string `json:"binding_roleref,omitempty" bson:"binding_roleref,omitempty"`
	BindSubject string `json:"binding_subject,omitempty" bson:"binding_subject,omitempty"`
}

// ************************************* ALARM SUMMARY *************************************
type KubeAlarmClusterInfo struct {
	ClusterId      string `json:"cluster_id,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
	ClusterArea    string `json:"cluster_area,omitempty"`
	RuleTypeFirst  string `json:"rule_type_1st,omitempty"`
	RuleTypeSecond string `json:"rule_type_2nd,omitempty"`
}
type KubeAlarmBaseInfo struct {
	AlarmType    string   `json:"alarm_type"`
	AlarmLevel   string   `json:"level"`
	Status       int      `json:"status"`
	UpdateTime   int64    `json:"update_time"`
	AlertDesc    string   `json:"alert_desc"`
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

type KubeAlarmSummaryResponse struct {
	DataType     string                    `json:"data_type"`
	BaseInfo     KubeAlarmClusterInfo      `json:"alarm_cluster_info,omitempty"`
	AlarmInfo    KubeAlarmBaseInfo         `json:"base_alarm_info,omitempty"`
	AuditLogInfo KubeAuditLogDbRiskData    `json:"cluster_auditlog_info,omitempty"`
	Plus9004     *KubeAuditLogDataPlus9004 `json:"plus_alarm_info_9004,omitempty"`
	Plus9005     *KubeAuditLogDataPlus9005 `json:"plus_alarm_info_9005,omitempty"`
	Plus9006     *KubeAuditLogDataPlus9006 `json:"plus_alarm_info_9006,omitempty"`
	Plus9007     *KubeAuditLogDataPlus9007 `json:"plus_alarm_info_9007,omitempty"`
	Plus9008     *KubeAuditLogDataPlus9008 `json:"plus_alarm_info_9008,omitempty"`
	Plus9009     *KubeAuditLogDataPlus9009 `json:"plus_alarm_info_9009,omitempty"`
	Plus9010     *KubeAuditLogDataPlus9010 `json:"plus_alarm_info_9010,omitempty"`
}

// ************************************* ALARM LIST *************************************

type KubeAlarmFilter struct {
	Name          string   `json:"name,omitempty" bson:"name,omitempty"`
	ClusterId     string   `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterRegion string   `json:"cluster_region,omitempty" bson:"cluster_region,omitempty"`
	ClusterName   string   `json:"cluster_name,omitempty" bson:"cluster,omitempty"`
	StatusList    []int    `json:"status,omitempty" bson:"status,omitempty"`
	TypeList      []string `json:"type,omitempty" bson:"type,omitempty"`
	LevelList     []string `json:"level,omitempty" bson:"level,omitempty"`
	StartTime     int64    `json:"time_start,omitempty" bson:"time_start,omitempty"`
	EndTime       int64    `json:"time_end,omitempty" bson:"time_end,omitempty"`
	EventName     string   `json:"event_name,omitempty" bson:"event_name,omitempty"`
	EventId       string   `json:"event_id,omitempty" bson:"event_id,omitempty"`
	EventReason   string   `json:"event_reason,omitempty" bson:"event_reason,omitempty"`
}

type KubeAlarmListRequest struct {
	Name          string   `json:"name,omitempty"`
	ClusterId     string   `json:"cluster_id,omitempty"`
	ClusterRegion string   `json:"cluster_region,omitempty"`
	ClusterName   string   `json:"cluster_name,omitempty"`
	Status        []int    `json:"status,omitempty"`
	TypeList      []string `json:"type,omitempty"`
	LevelList     []string `json:"level,omitempty"`
	StartTime     int64    `json:"time_start,omitempty"`
	EndTime       int64    `json:"time_end,omitempty"`
	EventName     string   `json:"event_name,omitempty"`
	EventId       string   `json:"event_id,omitempty"`
	EventReason   string   `json:"event_reason,omitempty"`
}

type KubeAlarmSimpleInfoItem struct {
	AlarmId     string `json:"_id,omitempty" bson:"_id,omitempty"`
	ClusterId   string `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty" bson:"cluster,omitempty"`
	ClusterArea string `json:"cluster_area,omitempty" bson:"cluster_area,omitempty"`
	RuleName    string `json:"rule_name,omitempty" bson:"rule_name,omitempty"`
	AlertType   string `json:"alert_type_us,omitempty" bson:"alert_type_us,omitempty"`
	Level       string `json:"level,omitempty" bson:"level,omitempty"`
	Status      int    `json:"__alarm_status,omitempty" bson:"__alarm_status,omitempty"`
	CreateTime  int64  `json:"__insert_time,omitempty" bson:"__insert_time,omitempty"`
}

type KubeAlarmListResponseItem struct {
	AlarmId     string               `json:"alarm_id"`
	ClusterId   string               `json:"cluster_id"`
	Status      int                  `json:"status"`
	Type        string               `json:"type"`
	Name        string               `json:"name"`
	Level       string               `json:"level"`
	AlarmTime   int64                `json:"alarm_time"`
	EventId     string               `json:"event_id"`
	EventName   string               `json:"event_name"`
	Attribution []AlarmAttribution   `json:"attribution_list"`
	Cluster     KubeAlarmClusterInfo `json:"cluster"`
	DataType    string               `json:"data_type"`
	TraceId     string               `json:"trace_id"`
}

type KubeAlarmExportDataRequest struct {
	AlarmIdList *[]string        `json:"alarm_id_list"`
	Conditions  *KubeAlarmFilter `json:"conditions"`
}

// ************************************* THREAT *************************************
type KubeAuditLogListFilterComm struct {
	ClusterId       string   `json:"cluster_id,omitempty"`
	ClusterName     string   `json:"cluster_name,omitempty"`
	Region          string   `json:"region,omitempty"`
	RiskNameList    []string `json:"risk_name_list,omitempty"`
	RiskLevelList   []string `json:"risk_level_list,omitempty"`
	SourceIp        string   `json:"source_ip,omitempty"`
	SourcePsm       string   `json:"source_psm,omitempty"`
	UserAgent       string   `json:"user_agent,omitempty"`
	User            string   `json:"user,omitempty"`
	UserGroup       string   `json:"user_group,omitempty"`
	CreateTimeStart int      `json:"create_time_start,omitempty"`
	CreateTimeEnd   int      `json:"create_time_end,omitempty"`
	ResKind         string   `json:"resource_kind,omitempty"`
	ResNamespace    string   `json:"resource_namespace,omitempty"`
	ResName         string   `json:"resource_name,omitempty"`
}

type KubeResourceInfo struct {
	Kind      string `json:"kind,omitempty" bson:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty" bson:"namespace,omitempty"`
	Name      string `json:"name,omitempty" bson:"name,omitempty"`
}

type KubeClientInfo struct {
	IP  string `json:"ip,omitempty" bson:"ip,omitempty"`
	PSM string `json:"psm,omitempty" bson:"psm,omitempty"`
}

type KubeThreatAnalysisListBaseItem struct {
	ClusterId    string           `json:"cluster_id,omitempty" bson:"cluster_id,omitempty"`
	ClusterName  string           `json:"cluster_name,omitempty" bson:"cluster,omitempty"`
	ClusterArea  string           `json:"region,omitempty" bson:"cluster_area,omitempty"`
	RuleName     string           `json:"risk_name,omitempty" bson:"rule_name,omitempty"`
	Level        string           `json:"risk_level,omitempty" bson:"level,omitempty"`
	UserAgent    string           `json:"user_agent,omitempty" bson:"user_agent,omitempty"`
	UserName     string           `json:"user,omitempty" bson:"real_user_name,omitempty"`
	UserGroup    []string         `json:"user_group_list,omitempty" bson:"real_user_groups,omitempty"`
	CreateTime   int64            `json:"create_time,omitempty" bson:"__insert_time,omitempty"`
	ResNamespace *string          `json:"resource_namespace,omitempty" bson:"resource_namespace,omitempty"`
	ResKind      *string          `json:"resource_kind,omitempty" bson:"resource_kind,omitempty"`
	ResName      *string          `json:"resource_name,omitempty" bson:"resource_name,omitempty"`
	SourceIP     *string          `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	SourceAsset  *string          `json:"source_ip_asset,omitempty" bson:"source_ip_asset,omitempty"`
	ResInfo      KubeResourceInfo `json:"resource_info,omitempty" bson:"resource_info,omitempty"`
	Source       KubeClientInfo   `json:"source_info,omitempty" bson:"source_info,omitempty"`
}

// AbnormalBehavior
type KubeAbnormalBehaviorFilter struct {
	KubeAuditLogListFilterComm `json:",inline" bson:",inline"`
	ActionList                 []string `json:"action_list,omitempty"`
}

type KubeAbnormalBehaviorListRequest struct {
	Condision KubeAbnormalBehaviorFilter `json:"condition,omitempty"`
}

type KubeAbnormalBehaviorListResponseItem struct {
	KubeThreatAnalysisListBaseItem `json:",inline" bson:",inline"`
	Action                         string `json:"action,omitempty" bson:"verb,omitempty"`
	Id                             string `json:"abnormal_id,omitempty" bson:"_id,omitempty"`
}

// ThreatResourceCreat
type KubeThreatResourceCreatFilter struct {
	KubeAuditLogListFilterComm `json:",inline" bson:",inline"`
	ImageName                  string `json:"image_name,omitempty"`
	ReadonlyMount              string `json:"read_only_mount,omitempty"`
	ReadwriteMount             string `json:"read_write_mount,omitempty"`
}

type KubeThreatResourceCreatListRequest struct {
	Condision KubeThreatResourceCreatFilter `json:"condition,omitempty"`
}

type KubeThreatResourceCreatListResponseItem struct {
	KubeThreatAnalysisListBaseItem `json:",inline" bson:",inline"`
	Id                             string   `json:"threatres_id,omitempty" bson:"_id,omitempty"`
	ImageList                      []string `json:"image_list,omitempty" bson:"images,omitempty"`
	ReadOnlyMountList              []string `json:"read_only_mount_list,omitempty" bson:"read_only_mounts,omitempty"`
	ReadWriteMountList             []string `json:"read_write_mount_list,omitempty" bson:"read_write_mounts,omitempty"`
}

// preview
type KubeThreatPreviewResponse struct {
	kube.KubeThreatStatistics `json:",inline" bson:",inline"`
}

// ************************************* CLUSTER INFO *************************************
type KubeClusterBaseInfo struct {
	ClusterId   string `bson:"cluster_id,omitempty"`
	ClusterName string `bson:"cluster_name,omitempty"`
	ClusterArea string `bson:"cluster_region,omitempty"`
}
