package config

type Nginx struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	SSHHost    []Host `yaml:"ssh_host"`
	Domain     string `yaml:"domain"`
	PublicAddr string `yaml:"publicaddr"`

	CdnList        []string `yaml:"cdn_list" json:"cdn_list"`
	UploadAddress  string   `yaml:"upload_address" json:"upload_address"`
	UploadUser     string   `yaml:"upload_user"`
	UploadPassword string   `yaml:"upload_password"`

	SDHost     []Host `yaml:"sd_host"`
	ACHost     []Host `yaml:"ac_host"`
	MGHost     Host   `yaml:"mg_host"`
	LeaderHost Host   `yaml:"leader_host"`
}
