package config

import "time"

type PrometheusClient struct {
	Address  string `yaml:"address"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type ReportComponent struct {
	Instances []string `yaml:"instances"`
}

type ReportConfig struct {
	EnableReport bool `yaml:"enable_report"`

	Uid   string `yaml:"uid"`
	Email string `yaml:"email"`

	HeartbeatUrl string `yaml:"heartbeat_url"`
	KoUrl        string `yaml:"ko_url"`

	ElkeidupVersion string    `yaml:"elkeidup_version"`
	DeployAt        time.Time `yaml:"deploy_at"`

	Prometheus PrometheusClient `yaml:"prometheus"`

	Components map[string]ReportComponent `yaml:"components"`
}
