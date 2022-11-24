package infra

import (
	"os"

	"github.com/bytedance/Elkeid/server/manager/infra/tos"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	ServerRegisterFormat = "%s_http"

	DefaultCollection = "default"

	UserCollection           = "user"
	AgentHeartBeatCollection = "agent_heartbeat"
	AgentTaskCollection      = "agent_task"
	AgentSubTaskCollection   = "agent_subtask"
	FileInfoCollection       = "file_upload"

	AgentConfigTemplate       = "agent_config_template"
	HubAlarmCollectionV1      = "hub_alarm_v1"
	HubWhiteListCollectionV1  = "hub_whitelist_v1"
	HubAlarmEventCollectionV1 = "hub_alarm_event_v1"

	VulnConfig         = "vuln_config"
	RaspVulnProcess    = "rasp_vuln_process"
	AgentVulnInfo      = "agent_vuln_info"
	AgentVulnSoftInfo  = "agent_vuln_soft_info"
	VulnHeartBeat      = "vuln_heartbeat"
	VulnInfoCollection = "vuln_info"
	CpeInfoCollection  = "cpe_info"
	VulnTaskStatus     = "vuln_task_status"
	VulnStatus         = "vuln_status"
	VulnProcess        = "vuln_process"

	SystemAlertCollectionV1 = "system_alert_v1"
	SystemAlertCollectionV2 = "system_alert_v2"

	BaseLineInfoColl      = "baseline_info"
	AgentBaselineColl     = "agent_baseline"
	BaselineGroupStatus   = "baseline_group_status"
	BaselineStatus        = "baseline_status"
	BaselineTaskStatus    = "baseline_task_status"
	BaselineCheckInfoColl = "baseline_check_info"
	BaselineGroupInfo     = "baseline_group_info"

	FingerprintRaspCollection = "agent_asset_2997"

	FingerprintProcessCollection      = "agent_asset_5050"
	FingerprintPortCollection         = "agent_asset_5051"
	FingerprintUserCollection         = "agent_asset_5052"
	FingerprintCrontabCollection      = "agent_asset_5053"
	FingerprintServiceCollection      = "agent_asset_5054"
	FingerprintSoftwareCollection     = "agent_asset_5055"
	FingerprintContainerCollection    = "agent_asset_5056"
	FingerprintIntegrityCollection    = "agent_asset_5057"
	FingerprintVolumeCollection       = "agent_asset_5058"
	FingerprintNetInterfaceCollection = "agent_asset_5059"
	FingerprintAppCollection          = "agent_asset_5060"

	FingerprintKmodCollection = "agent_asset_5062"

	CronjobCollection = "cronjob"

	// RASP
	RaspConfig                 = "rasp_config"
	RaspMethod                 = "rasp_method"
	RaspAlarmCollectionV1      = "rasp_alarm_v1"
	ComponentCollection        = "component"
	ComponentVersionCollection = "component_version"
	ComponentPolicyCollection  = "component_policy"
	RaspAlarmWhiteV1           = "rasp_alarm_white_v1"
	RaspEventCollectionV1      = "rasp_event_v1"

	// alarm stat
	HidsAlarmStatCollectionV1 = "hids_alarm_stat_v1"
	RaspAlarmStatCollectionV1 = "rasp_alarm_stat_v1"
	KubeAlarmStatCollectionV1 = "kube_alarm_stat_v1"

	// binary control
	BinaryControlChecksumResultCollection = "binarycontrol_checksum_result"

	// virus detection
	VirusDetectionCollectionV1         = "virus_detection_alarm_v1"
	VirusDetectionWhiteCollectionV1    = "virus_detection_alarm_white_v1"
	VirusDetectionTaskStatCollectionV1 = "virus_detection_task_stat_v1"

	// notice config
	NoticeConfigCollectionV1 = "notice_config_v1"

	// kubernetes security
	KubeAlarmCollectionV1            = "kube_alarm_v1"
	KubeAbnormalBehaviorCollectionV1 = "kube_abnormal_behavior_v1"
	KubeThreatResourceCreatV1        = "kube_threat_resource_creat_v1"
	KubeVulnExploitV1                = "kube_vuln_exploit_v1"
	KubeAlarmWhiteCollectionV1       = "kube_alarm_white_v1"
	KubeEventCollectionV1            = "kube_event_v1"
	KubeThreatStatisticsV1           = "kube_threat_stat_v1"

	// kubernetes cluster
	KubeClusterConfig = "kube_cluster_config"
	KubeClusterInfo   = "kube_cluster_info"
	KubeNodeInfo      = "kube_node_info"
	KubeWorkerInfo    = "kube_worker_info"
	KubePodInfo       = "kube_pod_info"
	KubeContainerInfo = "kube_container_info"

	AgentContainerInfoCollection     = "agent_asset_5056"
	FingerPrintRefreshTaskCollection = "fp_refresh_task"
)

var (
	Conf     *viper.Viper
	ConfPath string
	Sig      = make(chan os.Signal, 1)
	Quit     = make(chan bool)

	Grds          redis.UniversalClient
	MongoClient   *mongo.Client
	MongoDatabase string

	HttpPort  int
	ApiAuth   bool
	InnerAuth map[string]string
	Secret    string

	SvrName string
	SvrAK   string
	SvrSK   string

	SDAddrs      []string
	RegisterName string
	LocalIP      string
	SdAK         string
	SdSK         string
	HubAK        string
	HubSK        string
	AgentName    string

	TosClients  []tos.Client
	HubPluginNs string
)

func LookupCollection(t string) (c string) {
	switch t {
	case "process":
		c = FingerprintProcessCollection
	case "port":
		c = FingerprintPortCollection
	case "user":
		c = FingerprintUserCollection
	case "cron":
		c = FingerprintCrontabCollection
	case "service":
		c = FingerprintServiceCollection
	case "software":
		c = FingerprintSoftwareCollection
	case "container":
		c = FingerprintContainerCollection
	case "integrity":
		c = FingerprintIntegrityCollection
	case "app":
		c = FingerprintAppCollection
	case "kmod":
		c = FingerprintKmodCollection
	}
	return
}
func LookupGroupKey(t string) (c string) {
	switch t {
	case "process":
		c = "comm"
	case "port":
		c = "sport"
	case "user":
		c = "name"
	case "cron":
		c = "command"
	case "service":
		c = "name"
	case "software":
		c = "name"
	case "kmod":
		c = "name"
	case "app":
		c = "name"
	}
	return
}
