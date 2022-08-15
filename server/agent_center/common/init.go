package common

import (
	"flag"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common/kafka"
	"github.com/bytedance/Elkeid/server/agent_center/common/userconfig"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"os"
	"strings"
)

func init() {
	confPath := flag.String("c", "conf/svr.yml", "ConfigPath")
	flag.Parse()
	ConfPath = *confPath

	initConfig()
}

func initConfig() {
	var err error
	if UserConfig, err = userconfig.NewUserConfig(userconfig.WithPath(ConfPath)); err != nil {
		fmt.Printf("####LOAD_CONFIG_ERROR: %v", err)
		os.Exit(-1)
	}

	initLog()
	initDefault()
	initComponents()
}

func initDefault() {
	var err error
	LocalIP, err = GetOutboundIP()
	if err != nil {
		ylog.Fatalf("init", "GET_LOCALIP_ERROR: %s Error: %v", LocalIP, err)
	}

	SSLKeyFile = UserConfig.GetString("server.ssl.keyfile")
	SSLCertFile = UserConfig.GetString("server.ssl.certfile")
	SSLRawDataKeyFile = UserConfig.GetString("server.ssl.rawdata_keyfile")
	SSLRawDataCertFile = UserConfig.GetString("server.ssl.rawdata_certfile")
	SSLCaFile = UserConfig.GetString("server.ssl.cafile")
	if SSLKeyFile == "" || SSLCertFile == "" || SSLCaFile == "" || SSLRawDataKeyFile == "" || SSLRawDataCertFile == "" {
		ylog.Fatalf("init", "ssl file empty SSLKeyFile:%s SSLCertFile:%s SSLCaFile:%s SSLRawDataKeyFile:%s SSLRawDataCertFile:%s", SSLKeyFile, SSLCertFile, SSLCaFile, SSLRawDataKeyFile, SSLRawDataCertFile)
	}
	SvrName = UserConfig.GetString("sd.name")
	SdAddrs = UserConfig.GetStringSlice("sd.addrs")
	SvrAK = strings.ToLower(UserConfig.GetString("sd.auth.ak"))
	SvrSK = UserConfig.GetString("sd.auth.sk")

	ManageAddrs = UserConfig.GetStringSlice("manage.addrs")

	GRPCPort = UserConfig.GetInt("server.grpc.port")
	ConnLimit = UserConfig.GetInt("server.grpc.connlimit")

	HttpPort = UserConfig.GetInt("server.http.port")
	HttpSSLEnable = UserConfig.GetBool("server.http.ssl.enable")
	HttpAuthEnable = UserConfig.GetBool("server.http.auth.enable")
	HttpAkSkMap = UserConfig.GetStringMapString("server.http.auth.aksk")

	PProfEnable = UserConfig.GetBool("server.pprof.enable")
	PProfPort = UserConfig.GetInt("server.pprof.port")

	RawDataPort = UserConfig.GetInt("server.rawdata.port")
}

func initLog() {
	logLevel := UserConfig.GetInt("server.log.applog.loglevel")
	logPath := UserConfig.GetString("server.log.applog.path")
	logger := ylog.NewYLog(
		ylog.WithLogFile(logPath),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(logLevel),
	)
	ylog.InitLogger(logger)
}

func initComponents() {
	var (
		err error
	)
	//kafka
	kafkaAddr := UserConfig.GetStringSlice("kafka.addrs")
	kafkaTopic := UserConfig.GetString("kafka.topic")
	RawdataTopic := UserConfig.GetString("kafka.rawdata_topic")
	kafkaLog := UserConfig.GetString("kafka.logpath")
	kafkaEnable := UserConfig.GetBool("kafka.sasl.enable")
	kafkaUser := UserConfig.GetString("kafka.sasl.username")
	kafkaPassword := UserConfig.GetString("kafka.sasl.password")
	ylog.Infof("InitComponents", "KAFKA Producer: %v - %v", kafkaAddr, kafkaTopic)
	if KafkaProducer, err = kafka.NewProducerWithLog(kafkaAddr, kafkaTopic, fmt.Sprintf("sarama-%s", LocalIP), kafkaLog, kafkaUser, kafkaPassword, kafkaEnable); err != nil {
		fmt.Printf("#### %s %s CONNECT_KAFKA_ERROR: %v", kafkaAddr, kafkaTopic, err)
		ylog.Fatalf("InitComponents", "%s %s CONNECT_KAFKA_ERROR: %v", kafkaAddr, kafkaTopic, err)
	}

	ylog.Infof("InitComponents", "KAFKA Producer: %v - %v", kafkaAddr, RawdataTopic)
	if KafkaRawDataProducer, err = kafka.NewProducerWithLog(kafkaAddr, RawdataTopic, fmt.Sprintf("sarama-%s", LocalIP), kafkaLog, kafkaUser, kafkaPassword, kafkaEnable); err != nil {
		fmt.Printf("#### %s %s CONNECT_KAFKA_ERROR: %v", kafkaAddr, RawdataTopic, err)
		ylog.Fatalf("InitComponents", "%s %s CONNECT_KAFKA_ERROR: %v", kafkaAddr, RawdataTopic, err)
	}
}
