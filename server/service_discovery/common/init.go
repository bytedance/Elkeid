package common

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/common/redis"
	"github.com/bytedance/Elkeid/server/service_discovery/common/ylog"
	"github.com/fsnotify/fsnotify"
	rds "github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"os"
	"os/signal"
)

var (
	Sig  = make(chan os.Signal, 1)
	Quit = make(chan bool)
	V    *viper.Viper

	ConfigChangeNotify = make(chan bool, 1)
	RunMode            string
	Clusterkey         string
	SrvIp              string
	SrvPort            int

	AuthEnable bool
	AuthKeys   map[string]string

	Grds rds.UniversalClient
)

const (
	defaultConfigFile = "./conf/conf.yaml"
	RunModeRedis      = "redis"
	RunModeConfig     = "config"
)

func init() {
	//
	signal.Notify(Sig, os.Interrupt)
	//
	V = viper.New()
	V.SetConfigFile(defaultConfigFile)
	//watch config file
	V.WatchConfig()
	V.OnConfigChange(watchCallback)
	err := V.ReadInConfig()
	if err != nil {
		fmt.Printf("read in config error: %s\n", err.Error())
		os.Exit(1)
	}
	configNotify()
	//
	//
	logger := ylog.NewYLog(
		ylog.WithLogFile(V.GetString("log.path")),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(V.GetInt("log.loglevel")),
	)
	ylog.InitLogger(logger)
	//get config
	RunMode = V.GetString("Cluster.Mode")
	Clusterkey = V.GetString("Cluster.Key")
	SrvIp = V.GetString("Server.Ip")
	SrvPort = V.GetInt("Server.Port")

	AuthEnable = V.GetBool("Auth.Enable")
	AuthKeys = V.GetStringMapString("Auth.Keys")

	if RunMode == RunModeRedis {
		//connect redis
		if Grds, err = redis.NewRedisClient(V.GetStringSlice("Redis.Addrs"), V.GetString("Redis.MasterName"), V.GetString("Redis.Passwd")); err != nil {
			fmt.Println("NEW_REDIS_ERROR", err.Error())
			os.Exit(-1)
		}
	}
	return
}

func configNotify() {
	select {
	case ConfigChangeNotify <- true:
		fmt.Printf("notify config changed\n")
	default:
		fmt.Printf("config change notify channel is block\n")
	}
}

func watchCallback(e fsnotify.Event) {
	configNotify()
}
