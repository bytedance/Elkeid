package config

type PrometheusConf struct {
	PrometheusSelfAddr    string   `yaml:"prometheus_self_addr"`
	PrometheusUser        string   `yaml:"prometheus_user"`
	PrometheusPassword    string   `yaml:"prometheus_password"`
	AlertManagerAddrList  []string `yaml:"alert_manager_addr_list"`
	EnableRedis           bool     `yaml:"enable_redis"`
	RedisAddr             []string `yaml:"redis_addr"`
	RedisExporterAddr     string   `yaml:"redis_exporter_addr"`
	EnableKafka           bool     `yaml:"enable_kafka"`
	KafkaExporterAddr     string   `yaml:"kafka_exporter_addr"`
	EnableZookeeper       bool     `yaml:"enable_zookeeper"`
	ZookeeperExporterAddr string   `yaml:"zookeeper_exporter_addr"`
	EnableES              bool     `yaml:"enable_es"`
	ESExporterAddr        string   `yaml:"es_exporter_addr"`
	EnableMongodb         bool     `yaml:"enable_mongodb"`
	MongoExporterAddr     []string `yaml:"mongo_exporter_addr"`
	NodeExporterAddr      []string `yaml:"node_exporter_addr"`
	ProcessExporterAddr   []string `yaml:"process_exporter_addr"`
	EnableAC              bool     `yaml:"enable_ac"`
	AgentCenterAddr       []string `yaml:"agent_center_addr"`
	EnableSD              bool     `yaml:"enable_sd"`
	ServiceDiscoveryAddr  []string `yaml:"service_discovery_addr"`
	EnableHub             bool     `yaml:"enable_hub"`
	HubAddr               []string `yaml:"hub_addr"`
	EnableRemote          bool     `yaml:"enable_remote"`
	RemoteWriteUrl        string   `yaml:"remote_write_url"`
	RemoteReadUrl         string   `yaml:"remote_read_url"`
}

type Grafana struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	SSHHost            Host   `yaml:"ssh_host"`
	AdminPassword      string `yaml:"admin_password"`
	PrometheusUrl      string `yaml:"prometheus_url"`
	PrometheusPassword string `yaml:"prometheus_password"`
}

type Prometheus struct {
	BasicConfig
	Install bool `yaml:"install"`

	OriConf       map[string]interface{} `yaml:"ori_conf"`
	AdminPassword string                 `yaml:"admin_password"`
	SSHHost       []Host                 `yaml:"ssh_host"`
	Conf          []PrometheusConf       `yaml:"conf"`
}

type PrometheusAlertManager struct {
	BasicConfig
	Install bool `yaml:"install"`

	InstalledHosts []Host `yaml:"installed_hosts"`
	CallbackUrl    string `yaml:"callback_url"`
}

type Checker struct {
	BasicConfig
	Install bool `yaml:"install"`

	InstalledHosts []Host `yaml:"installed_hosts"`
}

type NodeExporter struct {
	BasicConfig
	Install bool `yaml:"install"`

	InstalledHosts []Host `yaml:"installed_hosts"`
}

type RedisExporter struct {
	BasicConfig
	Install bool `yaml:"install"`

	RedisPassword  string `yaml:"redis_password"`
	InstalledHosts []Host `yaml:"installed_hosts"`
}

type MongodbExporter struct {
	BasicConfig
	Install bool `yaml:"install"`

	AdminPassword string `yaml:"admin_password"`
	MongodbHosts  []Host `yaml:"mongodb_hosts"`
}

type KafkaExporter struct {
	BasicConfig
	Install bool `yaml:"install"`

	KafkaURI       string `yaml:"kafka_uri"`
	InstalledHosts []Host `yaml:"installed_hosts"`
}

type ZookeeperExporter struct {
	BasicConfig
	Install bool `yaml:"install"`

	InstalledHosts []Host `yaml:"installed_hosts"`
	ZookeeperHosts []Host `yaml:"zookeeper_hosts"`
}

type ESExporter struct {
	BasicConfig
	Install bool `yaml:"install"`

	ESHosts        []Host `yaml:"es_hosts"`
	InstalledHosts []Host `yaml:"installed_hosts"`
}
