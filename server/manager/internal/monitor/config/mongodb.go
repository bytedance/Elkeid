package config

type Mongodb struct {
	BasicConfig
	Install bool                   `yaml:"install"`
	OriConf map[string]interface{} `yaml:"ori_conf"`

	URI          string `yaml:"uri"`
	SSHHost      []Host `yaml:"ssh_host"`
	Model        string `yaml:"model"`
	DBName       string `yaml:"db_name"`
	AdminPasswd  string `yaml:"admin_passwd"`
	ElkeidPasswd string `yaml:"elkeid_passwd"`
}
