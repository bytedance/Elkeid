package common

import (
	"github.com/bytedance/Elkeid/server/agent_center/common/kafka"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/spf13/viper"
	"os"
)

const (
	PluginsStatusAllOnline     = "all_online"
	PluginsStatusAllOffline    = "all_offline"
	PluginsStatusAllSomeOnline = "some_online"
)

var (
	Sig = make(chan os.Signal, 1)

	UserConfig           *viper.Viper
	KafkaProducer        *kafka.Producer // send agent raw data
	KafkaRawDataProducer *kafka.Producer // k8s audit log

	ConfPath string
	LocalIP  string //server本地IP
	FileDir  string = "./file/"

	ManageAddrs []string // addrlist of Management Center

	SdAddrs []string // addrlist of service discovery center
	SvrName string   // Name registered to the service discovery center
	SvrAK   string   // access key, which use for http sign
	SvrSK   string   // secret key, which use for http sign

	GRPCPort  int //grpc
	ConnLimit int

	HttpPort           int
	HttpSSLEnable      bool
	SSLKeyFile         string
	SSLCertFile        string
	SSLRawDataKeyFile  string
	SSLRawDataCertFile string
	SSLCaFile          string
	HttpAuthEnable     bool
	HttpAkSkMap        map[string]string //access key and secret key list, which used to identify whether the http request comes from a known subject

	PProfEnable bool
	PProfPort   int //pprof

	RawDataPort int
	MonitorPort int

	UserName string
	Password string

	LinuxPluginsList   map[string]bool
	WindowsPluginsList map[string]bool
)

// 硬编码维护的字段列表信息
var (
	// AgentUpdateKeys Agent心跳如下字段一更新则马上同步到后端
	AgentUpdateKeys = []string{"state", "state_detail", "version",
		"pid", "limit_cpu", "limit_memory",
		"monitor_enable", "monitor_cpu_last_minute", "monitor_cpu_percent",
		"monitor_memory_last_minute", "monitor_memory_percent", "monitor_operate",
		"plugins_status", "abnormal_plugins_list"}

	// PluginsUpdateKeys 插件心跳如下字段一更新则马上同步到后端
	PluginsUpdateKeys = []string{"pversion", "pid"}

	// FloatHBFields 必须为Float类型的心跳字段
	FloatHBFields = []string{
		"cpu_usage", "mem_usage", "start_time",
	}

	// StringHBFields 必须为string类型的心跳字段
	StringHBFields = []string{
		"platform_version", "version", "host_serial", "host_id", "host_model", "host_vendor", "cpu_name",
	}
)

type ConfigReleaseInfo struct {
	AgentID string              `json:"agent_id"`
	Plugin  string              `json:"plugin"`
	Status  pb.ConfigStatusCode `json:"status"`
	Release uint64              `json:"release"`
}

type ConfigRefreshResponse struct {
	AgentID    string              `json:"agent_id"`
	PluginName string              `json:"plugin,omitempty"`
	SecretKey  string              `json:"secret_key,omitempty"`
	Version    string              `json:"version,omitempty"`
	Release    uint64              `json:"release,omitempty"`
	Status     pb.ConfigStatusCode `json:"status,omitempty"`
	Config     []*pb.ConfigDetail  `json:"configs,omitempty"`
}

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

type PluginsInfo struct {
	Name     string `json:"name"`
	Pversion string `json:"pversion"`
	Status   string `json:"status"`
}
