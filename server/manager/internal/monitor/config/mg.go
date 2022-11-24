package config

type MG struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	SSHHost       []Host         `yaml:"ssh_host"`
	Config        *ManagerConfig `yaml:"config"`
	RootPassword  string         `yaml:"root_password"`
	AdminPassword string         `yaml:"admin_password"`

	SDHost     []Host `yaml:"sd_host"`
	ESHost     []Host `yaml:"es_host"`
	ESUser     string `yaml:"es_user"`
	ESPassword string `yaml:"es_password"`
	Ak         string `yaml:"ak"`
	Sk         string `yaml:"sk"`
	RedisModel string `yaml:"redis_model"`
	RedisHost  []Host `yaml:"redis_host"`
	RedisPwd   string `yaml:"redis_pwd"`
	MongoUri   string `yaml:"mongo_uri"`
	DBName     string `yaml:"dbname"`
	HubCluster string `yaml:"hub_cluster"`
	HubInputID string `yaml:"hub_input_id"`
	LeaderAK   string `yaml:"leader_ak"`
	LeaderSK   string `yaml:"leader_sk"`
	ACHost     []Host `yaml:"ac_host"`
}

type ManagerConfig struct {
	HTTP struct {
		Port      int               `yaml:"port"`
		InnerAuth map[string]string `yaml:"innerauth"`
		ApiAuth   struct {
			Enable bool   `yaml:"enable"`
			Secret string `yaml:"secret"`
		} `yaml:"apiauth"`
	} `yaml:"http"`
	Log struct {
		Path     string `yaml:"path"`
		Loglevel int    `yaml:"loglevel"`
	} `yaml:"log"`
	Sd struct {
		Address     []string `yaml:"addrs"`
		Name        string   `yaml:"name"`
		Credentials struct {
			Ak string `yaml:"ak"`
			Sk string `yaml:"sk"`
		} `yaml:"credentials"`
	} `yaml:"sd"`
	Server struct {
		Name        string `yaml:"name"`
		Credentials struct {
			Ak string `yaml:"ak"`
			Sk string `yaml:"sk"`
		} `yaml:"credentials"`
	} `yaml:"server"`
	Redis struct {
		Address    []string `yaml:"addrs"`
		Passwd     string   `yaml:"passwd"`
		MasterName string   `yaml:"mastername"`
	} `yaml:"redis"`
	Mongo struct {
		URI    string `yaml:"uri"`
		Dbname string `yaml:"dbname"`
	} `yaml:"mongo"`
	Trace struct {
		Enable      bool   `yaml:"enable"`
		Cluster     string `yaml:"cluster"`
		InputID     string `yaml:"input_id"`
		RulesetID   string `yaml:"ruleset_id"`
		RaspCluster string `yaml:"rasp_cluster"`
	}
	Hub struct {
		Credentials struct {
			AK string `yaml:"ak"`
			SK string `yaml:"sk"`
		} `yaml:"credentials"`
	} `yaml:"hub"`
	ES struct {
		Host        []string `yaml:"host"`
		Gzip        bool     `yaml:"gzip"`
		Sniff       bool     `yaml:"sniff"`
		User        string   `yaml:"user"`
		Password    string   `yaml:"password"`
		CleanupDays int      `yaml:"cleanup_days"`
	} `yaml:"es"`
}

type MangerResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}
