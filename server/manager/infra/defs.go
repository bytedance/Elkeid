package infra

import (
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	DefaultCollection        = "default"
	UserCollection           = "user"
	AgentHeartBeatCollection = "agent_heartbeat"
	AgentTaskCollection      = "agent_task"
	AgentSubTaskCollection   = "agent_subtask"

	AgentConfigTemplate      = "agent_config_template"
	HubAlarmCollectionV1     = "hub_alarm_v1"
	HubAssetCollectionV1     = "hub_asset_v1"
	HubWhiteListCollectionV1 = "hub_whitelist_v1"
	AgentVulnInfo            = "agent_vuln_info"
	VulnInfoCollection       = "vuln_info"
	CpeInfoCollection        = "cpe_info"

	HIDSTraceRawDataV1 = "hids_trace_rawdata"
	HIDSTraceTaskV1    = "hids_trace_task"
)

var (
	Conf     *viper.Viper
	ConfPath string
	Sig      = make(chan os.Signal, 1)
	Quit     = make(chan bool)

	Grds          redis.UniversalClient
	MongoClient   *mongo.Client
	MongoDatabase string

	AccessKey string
	SecretKey string

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
)
