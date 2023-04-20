package config

import "time"

type DeployRecord struct {
	Component string    `yaml:"component_name"`
	Version   int       `yaml:"version"`
	Type      string    `yaml:"type"`
	Result    string    `yaml:"result"`
	Time      time.Time `yaml:"time"`
}
