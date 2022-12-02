package config

type MongodbLeaderData struct {
	BasicConfig
	Install    bool   `yaml:"install"`
	Password   string `yaml:"password"`
	MongoUri   string `yaml:"mongo_uri"`
	KafkaAuth  bool   `yaml:"kafka_auth"`
	KafkaUser  string `yaml:"kafka_user"`
	KafkaPwd   string `yaml:"kafka_pwd"`
	KafkaTopic string `yaml:"kafka_topic"`
	KafkaHost  []Host `yaml:"kafka_host"`
	SSHHost    []Host `yaml:"ssh_host"`
	ESHost     []Host `yaml:"es_host"`
	ESUser     string `yaml:"es_user"`
	ESPassword string `yaml:"es_password"`
}

type MongodbManagerData struct {
	BasicConfig
	Install  bool   `yaml:"install"`
	Password string `yaml:"password"`
	SSHHost  []Host `yaml:"ssh_host"`
}
