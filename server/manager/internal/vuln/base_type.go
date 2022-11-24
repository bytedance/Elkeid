package vuln

type AgentVulnSoftInfo struct {
	AgentId        string `json:"agent_id" bson:"agent_id"`
	VulnId         int64  `json:"vuln_id" bson:"vuln_id"`
	Type           string `json:"type" bson:"type"`
	PackageName    string `json:"software_name" bson:"package_name"`
	PackageVersion string `json:"software_version" bson:"package_version"`
	PackageSource  string `json:"software_source" bson:"package_source"`
	PackagePath    string `json:"software_path" bson:"package_path"`
	ContainerName  string `json:"container_name" bson:"container_name"`
	ContainerId    string `json:"container_id" bson:"container_id"`
	Cmdline        string `json:"cmdline" bson:"cmdline"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
	PidList        []struct {
		Pid string `json:"pid" bson:"pid"`
		Cmd string `json:"cmd" bson:"cmd"`
	} `json:"pid_list" bson:"pid_list"`
}

type AgentVulnInfo struct {
	AgentId       string   `json:"agent_id" bson:"agent_id"`
	VulnId        int64    `json:"vuln_id" bson:"vuln_id"`
	CveId         string   `json:"cve_id" bson:"cve_id"`
	Tag           []string `json:"tag" bson:"tag"`
	VulnName      string   `json:"vuln_name" bson:"vuln_name"`
	Status        string   `json:"status" bson:"status"`
	Level         string   `json:"level" bson:"level"`
	CreateTime    int64    `json:"create_time" bson:"create_time"`
	UpdateTime    int64    `json:"update_time" bson:"update_time"`
	ControlTime   int64    `json:"control_time" bson:"control_time"`
	DropStatus    string   `json:"drop_status" bson:"drop_status"`
	Action        string   `json:"action" bson:"action"`
	OperateReason string   `json:"operate_reason" bson:"operate_reason"`
}

type VulnInfo struct {
	VulnName   string `json:"vuln_name" bson:"title_cn"`
	CveId      string `json:"cve_id" bson:"cve"`
	Level      string `json:"level" bson:"severity"`
	CpeName    string `json:"cpe_name" bson:"cpe_product"`
	CpeVersion string `json:"cpe_version" bson:"cpe_version"`
	IfExp      int64  `json:"if_exp" bson:"has_payload"`
	Descript   string `json:"descript" bson:"description_cn"`
	Suggest    string `json:"suggest" bson:"solution_cn"`
	ReferUrls  string `json:"refer_urls" bson:"vuln_references"`
	Cwe        string `json:"cwe" bson:"vuln_type_cn"`
	VulnId     int64  `json:"vuln_id" bson:"id"`
	VulnNameEn string `json:"vuln_name_en" bson:"title_en"`
	DescriptEn string `json:"descript_en" bson:"description_en"`
	SuggestEn  string `json:"suggest_en" bson:"solution_en"`
	Action     string `json:"action" bson:"action"`
}

type CpeInfo struct {
	CpeName    string `json:"cpe_name" bson:"cpe_product"`
	CpeVersion string `json:"cpe_version" bson:"cpe_version"`
	Vendor     string `json:"vendor" bson:"cpe_vendor"`
}

type VulnTaskStatus struct {
	AgentId       string `json:"agent_id" bson:"agent_id"`
	Status        string `json:"status" bson:"status"`
	LastCheckTime int64  `json:"last_check_time" bson:"last_check_time"`
	Msg           string `json:"msg" bson:"msg"`
}

type VulnStatus struct {
	Id            int    `json:"id" bson:"id"`
	Status        string `json:"status" bson:"status"`
	LastCheckTime int64  `json:"last_check_time" bson:"last_check_time"`
}

type VulnHeart struct {
	VulnId       int64  `json:"vuln_id" bson:"vuln_id"`
	Level        string `json:"level" bson:"level"`
	InfectNum    int    `json:"infect_num" bson:"infect_num"`
	InfectStatus struct {
		Processed   int `json:"processed" bson:"processed"`
		UnProcessed int `json:"unprocessed" bson:"unprocessed"`
		Ignore      int `json:"ignore" bson:"ignore"`
	} `json:"infect_status" bson:"infect_status"`
	CveId         string   `json:"cve_id" bson:"cve_id"`
	VulnName      string   `json:"vuln_name" bson:"vuln_name"`
	VulnNameEn    string   `json:"vuln_name_en" bson:"vuln_name_en"`
	Tag           []string `json:"tag" bson:"tag"`
	Status        string   `json:"status" bson:"status"`
	Action        string   `json:"action" bson:"action"`
	UpdateTime    int64    `json:"update_time" bson:"update_time"`
	ControlTime   int64    `json:"control_time" bson:"control_time"`
	OperateReason string   `json:"operate_reason" bson:"operate_reason"`
}

type VulnConfUpdate struct {
	Type           string `json:"type" bson:"type"`
	VulnLibVersion int64  `json:"vuln_lib_version" bson:"vuln_lib_version"`
	CpeLibVersion  int64  `json:"cpe_lib_version" bson:"cpe_lib_version"`
	IfAutoUpdate   bool   `json:"if_auto_update" bson:"if_auto_update"`
}
type VulnDaily struct {
	Date    int64 `json:"date" bson:"date"`
	VulnNum int64 `json:"vuln_num" bson:"vuln_num"`
}
type VulnConf7Day struct {
	Type     string      `json:"type" bson:"type"`
	Day7List []VulnDaily `json:"7day_list" bson:"7day_list"`
}

type VulnProcessInfo struct {
	AgentId       string   `json:"agent_id" bson:"agent_id"`
	VulnId        int64    `json:"vuln_id" bson:"vuln_id"`
	Pid           string   `json:"pid" bson:"pid"`
	Cve           string   `json:"cve" bson:"cve"`
	Cmd           string   `json:"cmd" bson:"cmd"`
	Tag           []string `json:"tag" bson:"tag"`
	Severity      string   `json:"severity" bson:"severity"`
	TitleCn       string   `json:"title_cn" bson:"title_cn"`
	CreateTime    int64    `json:"create_time" bson:"create_time"`
	UpdateTime    int64    `json:"update_time" bson:"update_time"`
	ControlTime   int64    `json:"control_time" bson:"control_time"`
	OperateReason string   `json:"operate_reason" bson:"operate_reason"`
}

//goland:noinspection GoUnusedConst,GoUnusedConst
const (
	VulnStatusUnProcessed = "unprocessed"
	VulnStatusProcessed   = "processed"
	VulnStatusIgnored     = "ignored"
	LowLevel              = "low"
	MidLevel              = "mid"
	HighLevel             = "high"
	DangerLevel           = "danger"
	VulnDropStatusUse     = "using"
	VulnDropStatusReserve = "reserve"
	VulnDropStatusDrop    = "drop"
	VulnActionBlock       = "block"
	VulnActionVisible     = "visible"
	VulnActionInvisible   = "invisible"
	VulnConfAutoUpdate    = "autoupdate"
	VulnConf7DayList      = "7day_list"
	VulnTaskDataType      = 5055

	HasEXP          = "存在EXP"
	VulnTaskTimeout = 1800 // 任务超时30分钟
	LargeAgent      = 2000 // 超过5000认为是大量agent

)
