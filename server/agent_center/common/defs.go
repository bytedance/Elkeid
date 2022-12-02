package common

import (
	"github.com/bytedance/Elkeid/server/agent_center/common/kafka"
	"github.com/spf13/viper"
	"os"
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
)
