package alarm_whitelist

// ############################### Variable ###############################
const (
	WhitelistRangeTypeAll    int = 0
	WhitelistRangeTypeSingle int = 1
)

const (
	WhitelistMatchKeyUnkownIndex int    = -1
	WhitelistMatchKeyEqIndex     int    = 0
	WhitelistMatchKeyEqValue     string = "$eq"
	WhitelistMatchKeyRegexIndex  int    = 1
	WhitelistMatchKeyRegexValue  string = "$regex"
)

const (
	WhitelistKeyAgentID   string = "agent_id"
	WhitelistKeyClusterID string = "cluster_id"
	WhitelistKeyName      string = "SMITH_ALERT_DATA.RULE_INFO.RuleName"
	WhitelistKeyKcPrefix  string = "node_list."
	WhitelistKeyRaspName  string = "rule_name"
)

const (
	WhitelistTypeHids  string = "hids"
	WhitelistTypeRasp  string = "rasp"
	WhitelistTypeKube  string = "kube"
	WhitelistTypeVirus string = "virus"
)

var WhitelistMatchTypeMap = map[int]string{
	WhitelistMatchKeyEqIndex:    "$eq",
	WhitelistMatchKeyRegexIndex: "$regex",
}

const (
	WhitelistRangeIndexTypeCluster string = "cluster"
)

var WhitelistKeyDbFieldMap = map[string]string{
	"argv":               "argv",
	"exe":                "exe",
	"md5_hash":           "md5_hash",
	"ppid_argv":          "ppid_argv",
	"pgid_argv":          "pgid_argv",
	"socket_argv":        "socket_argv",
	"sip":                "sip",
	"connect_info":       "connect_info",
	"pid_tree":           "pid_tree",
	"ld_preload":         "ld_preload",
	"ko_file":            "ko_file",
	"module_name":        "module_name",
	"run_path":           "run_path",
	"top_chain":          "top_chain",
	"static_file":        "static_file",
	"name":               "name",
	"class":              "class",
	"stack_trace_hash":   "stack_trace_hash",
	"stack_trace":        "stack_trace",
	"source_ip":          "source_ip",
	"user_agent":         "user_agent",
	"real_user_name":     "real_user_name",
	"real_user_groups":   "real_user_groups",
	"verb":               "verb",
	"resource_namespace": "resource_namespace",
	"resource_kind":      "resource_kind",
	"resource_name":      "resource_name",
	"images":             "images",
	"read_write_mounts":  "read_write_mounts",
	"read_only_mounts":   "read_only_mounts",
	"exec_command":       "exec_command",
	"args_array":         "args_array",
}
