package config

type Redis struct {
	BasicConfig
	Install   bool                   `yaml:"install"`
	RedisHost []Host                 `yaml:"redis_host"`
	SSHHost   []Host                 `yaml:"ssh_host"`
	Password  string                 `yaml:"password"`
	Model     string                 `yaml:"model"`
	OriConf   map[string]interface{} `yaml:"ori_conf"`
}
