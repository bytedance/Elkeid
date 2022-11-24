package alarm

// alarm type
const (
	AlarmTypeHids  string = "hids"
	AlarmTypeRasp  string = "rasp"
	AlarmTypeKube  string = "kube"
	AlarmTypeVirus string = "virus"
)

// alarm level
const (
	AlarmLevelCritical string = "critical"
	AlarmLevelHigh     string = "high"
	AlarmLevelMedium   string = "medium"
	AlarmLevelLow      string = "low"
)

const (
	AlarmDataMarkEmpty string = "-"
)

const (
	AlarmStatusByEndpointProcessing = 3

	AlarmStatusHandleByEndpointFailure = 5
)

const (
	AdfnAlarmStatus   = "__alarm_status"
	AdfnAlarmHitWhite = "__hit_wl"

	AdfnEventId      = "event_id"
	AdfnEventName    = "event_name"
	AdfnAgentId      = "agent_id"
	AdfnHostname     = "hostname"
	AdfnHostInIpv4   = "in_ipv4_list"
	AdfnHostOutIpv4  = "ex_ipv4_list"
	AdfnHostInIpv6   = "in_ipv6_list"
	AdfnHostOutIpv6  = "ex_ipv6_list"
	AdfnInsertTime   = "__insert_time"
	AdfnRuleName     = "SMITH_ALERT_DATA.RULE_INFO.RuleName"
	AdfnLevel        = "SMITH_ALERT_DATA.RULE_INFO.HarmLevel"
	AdfnAlertType    = "alert_type_us"
	AdfnReasonIp     = "reason_ip"
	AdfnReasonFile   = "reason_file"
	AdfnReasonSid    = "reason_sid"
	AdfnKcReasonIp   = "reason_ip_list"
	AdfnKcReasonFile = "reason_file_list"

	AdfnStaticFilePath = "static_file"
	AdfnStaticFileHash = "md5_hash"
	AdfnHandlerUser    = "__handler_user"
	AdfnUpdateTime     = "__update_time"
	AdfnErrorReason    = "__error_reason"
	AdfnTaskToken      = "token"

	AdfnClusterId            = "cluster_id"
	AdfnClusterName          = "cluster"
	AdfnClucsterArea         = "cluster_region"
	AdfnReasonKubeSrcIp      = "source_ip"
	AdfnReasonKubeUA         = "user_agent"
	AdfnReasonKubeUserName   = "user_name"
	AdfnReasonKubeUserGroup  = "user_groups"
	AdfnReasonKubeIUserName  = "impersonated_user_name"
	AdfnReasonKubeIUserGroup = "impersonated_user_groups"
)

const (
	AlarmAggregateFieldId    = "_id"
	AlarmAggregateFieldCount = "count"
)
