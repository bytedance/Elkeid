package config

type Kafka struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	PartitionNum int `yaml:"partition_num"`

	SkipCheck bool   `yaml:"skip_check"`
	Topic     string `yaml:"topic"`
	KafkaHost []Host `yaml:"kafka_host"`
	Zookeeper []Host `yaml:"zookeeper"`
	ZkConnect string `yaml:"zk_connect"`
	ZkServers string `yaml:"zk_servers"`
	SSHHost   []Host `yaml:"ssh_host"`
	Auth      bool   `yaml:"auth"`
	Username  string `yaml:"username"`
	Passwd    string `yaml:"passwd"`
}
