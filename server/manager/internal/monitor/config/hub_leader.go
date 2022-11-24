package config

type HubLeader struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	LeaderHost  Host   `yaml:"leader_host"`
	SSHHost     Host   `yaml:"ssh_host"`
	PORT0       string `yaml:"port0"`
	PORT1       string `yaml:"port1"`
	HUBPassword string `yaml:"hub_password"`

	SdHost     []Host `yaml:"sd_host"`
	MongoUri   string `yaml:"mongo_uri"`
	RedisModel string `yaml:"redis_model"`
	RedisHost  []Host `yaml:"redis_host"`
	RedisPwd   string `yaml:"redis_pwd"`
	Ak         string `yaml:"ak"`
	Sk         string `yaml:"sk"`
	KafkaHost  []Host `yaml:"kafka_host"`
	KafkaTopic string `yaml:"kafka_topic"`
	HubHost    Host   `yaml:"hub_host"`
}
