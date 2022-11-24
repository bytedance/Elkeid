package monitor

import (
	"github.com/bytedance/Elkeid/server/manager/internal/monitor/config"
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

var Config config.Config

func InitByConfigFile(filePath string) {
	bs, err := os.ReadFile(filePath)
	if err != nil {
		log.Println("Read elkeidup config error: ", err.Error())
		return
	}

	err = yaml.Unmarshal(bs, &Config)
	if err != nil {
		log.Println("Unmarshal elkeidup config error: ", err.Error())
		return
	}
	if len(Config.Prometheus.SSHHost) != 0 {
		PromCli.Address = "http://" + Config.Prometheus.SSHHost[0].Host + ":9090"
		PromCli.User = "admin"
		PromCli.Password = Config.Prometheus.AdminPassword
	}
}

func InitConfig() {
	InitByConfigFile("./conf/elkeidup_config.yaml")
	return
}
