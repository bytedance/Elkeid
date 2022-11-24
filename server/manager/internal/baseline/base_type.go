package baseline

// 策略组信息
type GroupInfo struct {
	GroupId      int            `json:"group_id" bson:"group_id"`
	GroupName    string         `json:"group_name" bson:"group_name"`
	GroupNameEn  string         `json:"group_name_en" bson:"group_name_en"`
	BaselineList []BaselineInfo `json:"baseline_list" bson:"baseline_list"`
}

// 基线信息
type BaselineInfo struct {
	BaselineId      int         `json:"baseline_id" bson:"baseline_id"`
	BaselineVersion string      `json:"baseline_version" bson:"baseline_version"`
	BaselineName    string      `json:"baseline_name" bson:"baseline_name"`
	Status          string      `json:"status" bson:"status"`
	Msg             string      `json:"msg" bson:"msg"`
	CheckIdList     []int       `json:"check_id_list" bson:"check_id_list"`
	CheckList       []CheckInfo `json:"check_list" bson:"check_list"`
	SystemList      []string    `json:"system_list" bson:"system_list"`
}

// 检查项信息
type CheckInfo struct {
	BaselineId    int    `yaml:"baseline_id" bson:"baseline_id" json:"baseline_id"`
	CheckId       int    `yaml:"check_id" bson:"check_id" json:"check_id"`
	BaselineCheck string `yaml:"baseline_check" bson:"baseline_check" json:"baseline_check"`
	Type          string `yaml:"type" bson:"type" json:"type"`
	Title         string `yaml:"title" bson:"title" json:"title"`
	Description   string `yaml:"description" bson:"description" json:"description"`
	Solution      string `yaml:"solution" bson:"solution" json:"solution"`
	Security      string `yaml:"security" bson:"security" json:"security"`
	TitleCn       string `yaml:"title_cn" bson:"title_cn" json:"title_cn"`
	TypeCn        string `yaml:"type_cn" bson:"type_cn" json:"type_cn"`
	DescriptionCn string `yaml:"description_cn" bson:"description_cn" json:"description_cn"`
	SolutionCn    string `yaml:"solution_cn" bson:"solution_cn" json:"solution_cn"`
	UpdateTime    int64  `yaml:"update_time" bson:"update_time" json:"update_time"`

	Result int    `json:"result" bson:"result"`
	Msg    string `json:"msg" bson:"msg"`

	PassRate int    `json:"pass_rate" bson:"pass_rate"`
	Status   string `json:"status" bson:"status"`
}

// 基线策略组状态
type BaselineGroupStatus struct {
	GroupId       int    `json:"group_id" bson:"group_id"`
	BaselineList  []int  `json:"baseline_list" bson:"baseline_list"`
	LastCheckTime int64  `json:"last_check_time" bson:"last_check_time"`
	Status        string `json:"status" bson:"status"`
}

// 基线状态
type BaselineStatus struct {
	BaselineId     int    `json:"baseline_id" bson:"baseline_id"`
	BaselineName   string `json:"baseline_name" bson:"baseline_name"`
	BaselineNameEn string `json:"baseline_name_en" bson:"baseline_name_en"`
	CheckNum       int    `json:"check_num" bson:"check_num"`
	LastCheckTime  int64  `json:"last_check_time" bson:"last_check_time"`
	Status         string `json:"status" bson:"status"`
}

// 基线主机任务状态
type BaselineTaskStatus struct {
	AgentId       string   `json:"agent_id" bson:"agent_id"`
	BaselineId    int      `json:"baseline_id" bson:"baseline_id"`
	LastCheckTime int64    `json:"last_check_time" bson:"last_check_time"`
	HighRiskNum   int      `json:"high_risk_num" bson:"high_risk_num"`
	MediumRiskNum int      `json:"medium_risk_num" bson:"medium_risk_num"`
	LowRiskNum    int      `json:"low_risk_num" bson:"low_risk_num"`
	PassNum       int      `json:"pass_num" bson:"pass_num"`
	Status        string   `json:"status" bson:"status"`
	Msg           string   `json:"msg" bson:"msg"`
	Hostname      string   `json:"hostname" bson:"hostname"`
	Tags          []string `json:"tags" bson:"tags"`
	ExtranetIpv4  []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	IntranetIpv4  []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
}

// 基线检查结果
type AgentBaselineInfo struct {
	AgentId         string   `json:"agent_id" bson:"agent_id"`
	BaselineId      int64    `json:"baseline_id" bson:"baseline_id"`
	BaselineVersion string   `json:"baseline_version" bson:"baseline_version"`
	CheckId         int64    `json:"check_id" bson:"check_id"`
	Type            string   `json:"type" bson:"type"`
	CheckName       string   `json:"check_name" bson:"check_name"`
	Description     string   `json:"description" bson:"description"`
	Solution        string   `json:"solution" bson:"solution"`
	TypeCn          string   `json:"type_cn" bson:"type_cn"`
	CheckNameCn     string   `json:"check_name_cn" bson:"check_name_cn"`
	DescriptionCn   string   `json:"description_cn" bson:"description_cn"`
	SolutionCn      string   `json:"solution_cn" bson:"solution_cn"`
	CheckLevel      string   `json:"check_level" bson:"check_level"`
	Status          string   `json:"status" bson:"status"`
	CreateTime      int64    `json:"create_time" bson:"create_time"`
	UpdateTime      int64    `json:"update_time" bson:"update_time"`
	IfWhite         bool     `json:"if_white" bson:"if_white"`
	WhiteReason     string   `json:"white_reason" bson:"white_reason"`
	ErrReason       string   `json:"err_reason" bson:"err_reason"`
	TaskStatus      string   `json:"task_status" bson:"task_status"`
	Hostname        string   `json:"hostname" bson:"hostname"`
	Tags            []string `json:"tags" bson:"tags"`
	ExtranetIpv4    []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	IntranetIpv4    []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
}

const (
	BaselineDataType       = 8000
	WeakPassDataType       = 5052
	DefaultBaseLineVersion = "1.0"
	WeakPassBaseline       = 5000
	BaselinCheckTimeout    = "检测超时，请检查baseline插件是否正常运行"

	StatusSuccess       = "success"
	StatusFailed        = "failed"
	BaselineTaskTimeout = 600 // 任务超时10分钟
	BaselineCheckHigh   = "high"
	BaselineCheckMid    = "mid"
	BaselineCheckLow    = "low"
)

var (
	BaselineAllIdList = []int{1200, 1300, 1400, 2200, 2300, 2400, 3200, 3300, 3400, 5000, 6000}
)
