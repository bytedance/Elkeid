package config

type HUB struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	Host       Host   `yaml:"host"`
	SSHHost    Host   `yaml:"ssh_host"`
	PORT0      string `yaml:"port0"`
	PORT1      string `yaml:"port1"`
	RedisModel string `yaml:"redis_model"`
	RedisHost  []Host `yaml:"redis_host"`
	RedisPwd   string `yaml:"redis_pwd"`
	LeaderHost Host   `yaml:"leader_host"`
	MgHost     []Host `yaml:"mg_host"`
	SdHost     []Host `yaml:"sd_host"`
	Ak         string `yaml:"ak"`
	Sk         string `yaml:"sk"`
	MgPwd      string `yaml:"mg_pwd"`
	LeaderPwd  string `yaml:"leader_pwd"`
}
