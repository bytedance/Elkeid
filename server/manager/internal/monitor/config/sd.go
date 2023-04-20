package config

type AkSkModel struct {
	Ak string `yaml:"ak"`
	Sk string `yaml:"sk"`
}

type SD struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	SSHHost    []Host                  `yaml:"ssh_host"`
	MgKeys     AkSkModel               `yaml:"mg_keys"`
	AcKeys     AkSkModel               `yaml:"ac_keys"`
	LeaderKeys AkSkModel               `yaml:"leader_keys"`
	Config     *ServiceDiscoveryConfig `yaml:"config"`
}

// ServiceDiscoveryConfig 默认只支持安装在8088端口
type ServiceDiscoveryConfig struct {
	Server struct {
		IP   string `yaml:"Ip"`
		Port int    `yaml:"Port"`
	} `yaml:"Server"`
	Cluster struct {
		Mode    string   `yaml:"Mode"`
		Members []string `yaml:"Members"`
	} `yaml:"Cluster"`
	Log struct {
		Path     string `yaml:"path"`
		Loglevel int    `yaml:"loglevel"`
	} `yaml:"log"`
	Auth struct {
		Enable bool              `yaml:"Enable"`
		Keys   map[string]string `yaml:"Keys"`
	} `yaml:"Auth"`
}

type SDDetailResp struct {
	Data []struct {
		Name     string `yaml:"name" json:"name"`
		IP       string `yaml:"ip" json:"ip"`
		Port     int    `yaml:"port" json:"port"`
		Status   int    `yaml:"status" json:"status"`
		CreateAt int    `yaml:"create_at" json:"create_at"`
		UpdateAt int    `yaml:"update_at" json:"update_at"`
		Weight   int    `yaml:"weight" json:"weight"`
		Extra    struct {
		} `json:"extra"`
	} `json:"data"`
	Msg string `json:"msg"`
}
