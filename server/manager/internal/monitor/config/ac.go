package config

type AC struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	SSHHost []Host             `yaml:"ssh_host"`
	Config  *AgentCenterConfig `yaml:"config"`

	GrpcConnLimit int `yaml:"grpc_conn_limit"`

	KafkaTopic        string `yaml:"kafka_topic"`
	KafkaRawDataTopic string `yaml:"kafka_rawdata_topic"`
	KafkaHost         []Host `yaml:"kafka_host"`
	KafkaAuth         bool   `yaml:"kafka_auth"`
	KafkaUser         string `yaml:"kafka_user"`
	KafkaPwd          string `yaml:"kafka_pwd"`
	MGHost            []Host `yaml:"mg_host"`
	AcAk              string `yaml:"ac_ak"`
	AcSk              string `yaml:"ac_sk"`
	MgAk              string `yaml:"mg_ak"`
	MgSk              string `yaml:"mg_sk"`
	SDHost            []Host `yaml:"sd_host"`
}

type AgentCenterConfig struct {
	Manage struct {
		Address []string `yaml:"addrs"`
	} `yaml:"manage"`
	Sd struct {
		Name    string   `yaml:"name"`
		Address []string `yaml:"addrs"`
		Auth    struct {
			Ak string `yaml:"ak"`
			Sk string `yaml:"sk"`
		} `yaml:"auth"`
	} `yaml:"sd"`
	Kafka struct {
		Address      []string `yaml:"addrs"`
		Topic        string   `yaml:"topic"`
		RawdataTopic string   `yaml:"rawdata_topic"`
		Sasl         struct {
			Enable   bool   `yaml:"enable"`
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		} `yaml:"sasl"`
		LogPath string `yaml:"logpath"`
	} `yaml:"kafka"`
	Server struct {
		Log struct {
			AppLog struct {
				Path     string `yaml:"path"`
				Loglevel int    `yaml:"loglevel"`
			} `yaml:"applog"`
		} `yaml:"log"`
		Ssl struct {
			Keyfile         string `yaml:"keyfile"`
			CertFile        string `yaml:"certfile"`
			RawDataCertFile string `yaml:"rawdata_certfile"`
			CaFile          string `yaml:"cafile"`
			RawDataKeyfile  string `yaml:"rawdata_keyfile"`
		} `yaml:"ssl"`
		Grpc struct {
			Port      int `yaml:"port"`
			ConnLimit int `yaml:"connlimit"`
		} `yaml:"grpc"`
		HTTP struct {
			Port int `yaml:"port"`
			Auth struct {
				Enable bool              `yaml:"enable"`
				AkSk   map[string]string `yaml:"aksk"`
			} `yaml:"auth"`
			Ssl struct {
				Enable bool `yaml:"enable"`
			} `yaml:"ssl"`
		} `yaml:"http"`
		Pprof struct {
			Enable bool `yaml:"enable"`
			Port   int  `yaml:"port"`
		} `yaml:"pprof"`
		RawData struct {
			Port int `yaml:"port"`
		} `yaml:"rawdata"`
	} `yaml:"server"`
}
