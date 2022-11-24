package config

type Config struct {
	Status        string         `yaml:"status"`
	DeployRecords []DeployRecord `yaml:"deploy_records"`

	Version string `yaml:"version"`

	AcceptInformationCollected bool `yaml:"accept_information_collected"`

	Redis      Redis      `yaml:"redis"`
	Prometheus Prometheus `yaml:"prometheus"`
	Grafana    Grafana    `yaml:"grafana"`
	Kafka      Kafka      `yaml:"kafka"`
	Mongodb    Mongodb    `yaml:"mongodb"`
	Nginx      Nginx      `yaml:"nginx"`
	HUB        HUB        `yaml:"hub"`
	HubLeader  HubLeader  `yaml:"hub_leader"`
	SD         SD         `yaml:"sd"`
	AC         AC         `yaml:"ac"`
	MG         MG         `yaml:"mg"`

	Checker                Checker                `yaml:"checker"`
	NodeExporter           NodeExporter           `yaml:"node_exporter"`
	RedisExporter          RedisExporter          `yaml:"redis_exporter"`
	MongodbExporter        MongodbExporter        `yaml:"mongodb_exporter"`
	KafkaExporter          KafkaExporter          `yaml:"kafka_exporter"`
	ZookeeperExporter      ZookeeperExporter      `yaml:"zookeeper_exporter"`
	ESExporter             ESExporter             `yaml:"es_exporter"`
	PrometheusAlertManager PrometheusAlertManager `yaml:"prometheus_alert_manager"`

	MongodbLeaderData  MongodbLeaderData  `yaml:"mongodb_leader_data"`
	MongodbManagerData MongodbManagerData `yaml:"mongodb_manager_data"`

	Report ReportConfig `yaml:"report"`
}

type BasicConfig struct {
	Status string `yaml:"installed_stat" json:"installed_stat"`

	Version int   `yaml:"version" json:"version"`
	Quota   Quota `yaml:"quota" json:"quota"`
}

func (b BasicConfig) GetVersion() int {
	return b.Version
}

type Host struct {
	OriHost  string `yaml:"ori_host"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	User     string `yaml:"user"`
	KeyFile  string `yaml:"keyfile"`
}
