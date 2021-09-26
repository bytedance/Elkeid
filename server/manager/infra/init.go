package infra

import (
	"context"
	"flag"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/mongodb"
	"github.com/bytedance/Elkeid/server/manager/infra/redis"
	"github.com/bytedance/Elkeid/server/manager/infra/userconfig"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"os"
	"strings"
	"time"
)

func init() {
	confPath := flag.String("c", "conf/svr.yml", "ConfigPath")
	flag.Parse()
	ConfPath = *confPath

	InitConfig()
}

func initlog() {
	logger := ylog.NewYLog(
		ylog.WithLogFile(Conf.GetString("log.path")),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(Conf.GetInt("log.loglevel")),
	)
	ylog.InitLogger(logger)
}

func initComponents() {
	var err error

	//connect redis
	if Grds, err = redis.NewRedisClient(Conf.GetStringSlice("redis.addrs"), Conf.GetString("redis.passwd")); err != nil {
		fmt.Println("NEW_REDIS_ERROR", err.Error())
		os.Exit(-1)
	}

	//test if redis is ok!
	err = Grds.Set(context.Background(), "elkeid_manager_test", "test", time.Second).Err()
	if err != nil {
		fmt.Println("REDIS_ERROR", err.Error())
		os.Exit(-1)
	}

	//connect mongodb
	MongoDatabase = Conf.GetString("mongo.dbname")
	if MongoClient, err = mongodb.NewMongoClient(Conf.GetString("mongo.uri")); err != nil {
		fmt.Println("NEW_MONGO_ERROR", err.Error())
		os.Exit(-1)
	}
}

func initDefault() {
	var err error

	LocalIP, err = GetOutboundIP()
	if err != nil {
		ylog.Fatalf("init", "GET_LOCALIP_ERROR: %s Error: %v", LocalIP, err)
	}

	HttpPort = Conf.GetInt("http.port")
	ApiAuth = Conf.GetBool("http.apiauth.enable")
	Secret = Conf.GetString("http.apiauth.secret")
	InnerAuth = Conf.GetStringMapString("http.innerauth")

	SvrName = Conf.GetString("server.name")
	SvrAK = strings.ToLower(Conf.GetString("server.credentials.ak"))
	SvrSK = Conf.GetString("server.credentials.sk")

	SDAddrs = Conf.GetStringSlice("sd.addrs")
	RegisterName = Conf.GetString("sd.name")
	SdAK = strings.ToLower(Conf.GetString("sd.credentials.ak"))
	SdSK = Conf.GetString("sd.credentials.sk")

	K8sSecAddr = Conf.GetString("k8ssec.addr")
	K8sAK = Conf.GetString("k8ssec.credentials.ak")
	K8sSK = Conf.GetString("k8ssec.credentials.sk")
}

func InitConfig() {
	var (
		err error
	)
	//load config
	if Conf, err = userconfig.NewUserConfig(userconfig.WithPath(ConfPath)); err != nil {
		fmt.Println("NEW_CONFIG_ERROR", err.Error())
		os.Exit(-1)
	}

	initlog()
	initComponents()
	initDefault()
}
