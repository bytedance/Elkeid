package init

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/metrics"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/tos"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"github.com/bytedance/Elkeid/server/manager/internal/baseline"
	"github.com/bytedance/Elkeid/server/manager/internal/container"
	"github.com/bytedance/Elkeid/server/manager/internal/cronjob"
	"github.com/bytedance/Elkeid/server/manager/internal/distribute/job"
	"github.com/bytedance/Elkeid/server/manager/internal/login"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"github.com/bytedance/Elkeid/server/manager/internal/outputer"
	"github.com/bytedance/Elkeid/server/manager/internal/rasp"
	"github.com/bytedance/Elkeid/server/manager/internal/vuln"

	"github.com/bytedance/Elkeid/server/manager/infra/mongodb"
	"github.com/bytedance/Elkeid/server/manager/infra/redis"
	"github.com/bytedance/Elkeid/server/manager/infra/userconfig"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

func Initialize() error {
	var (
		err error
	)

	confPath := flag.String("c", "conf/svr.yml", "ConfigPath")
	flag.Parse()
	infra.ConfPath = *confPath

	//load config
	if infra.Conf, err = userconfig.NewUserConfig(userconfig.WithPath(infra.ConfPath)); err != nil {
		fmt.Println("NEW_CONFIG_ERROR", err.Error())
		return err
	}

	initLog()
	if err = initDefault(); err != nil {
		return err
	}
	if err = initComponents(); err != nil {
		return err
	}

	//Add you init code here
	initDistribute()
	atask.Init()
	initAlarmWhitelist()
	initKube()

	err = initMonitor()
	if err != nil {
		fmt.Println("INIT_MONITOR_CONFIG", err.Error())
	}
	metrics.Init()

	login.Init()
	baseline.InitBaseline()
	vuln.InitVuln()
	rasp.RaspInit()
	container.ContainerInit()
	outputer.InitOutput()
	cronjob.InitCronjob()

	initV6()
	// init end

	initIndexes()

	initTos()
	return nil
}

func initLog() {
	logger := ylog.NewYLog(
		ylog.WithLogFile(infra.Conf.GetString("log.path")),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(infra.Conf.GetInt("log.loglevel")),
	)
	ylog.InitLogger(logger)
}

func initComponents() error {
	var err error

	//connect redis
	if infra.Grds, err = redis.NewRedisClient(infra.Conf.GetStringSlice("redis.addrs"), infra.Conf.GetString("redis.mastername"), infra.Conf.GetString("redis.passwd")); err != nil {
		fmt.Println("NEW_REDIS_ERROR", err.Error())
		return err
	}

	//test if redis is ok!
	err = infra.Grds.Set(context.Background(), "elkeid_manager_test", "test", time.Second).Err()
	if err != nil {
		fmt.Println("REDIS_ERROR", err.Error())
		return err
	}

	//connect mongodb
	infra.MongoDatabase = infra.Conf.GetString("mongo.dbname")
	if infra.MongoClient, err = mongodb.NewMongoClient(infra.Conf.GetString("mongo.uri")); err != nil {
		fmt.Println("NEW_MONGO_ERROR", err.Error())
		return err
	}
	return nil
}

func initDefault() error {
	var err error

	infra.LocalIP, err = infra.GetOutboundIP()
	if err != nil {
		ylog.Fatalf("init", "GET_LOCALIP_ERROR: %s Error: %v", infra.LocalIP, err)
		return err
	}

	infra.HttpPort = infra.Conf.GetInt("http.port")
	infra.ApiAuth = infra.Conf.GetBool("http.apiauth.enable")
	infra.Secret = infra.Conf.GetString("http.apiauth.secret")
	infra.InnerAuth = infra.Conf.GetStringMapString("http.innerauth")

	infra.SvrName = infra.Conf.GetString("server.name")
	infra.SvrAK = strings.ToLower(infra.Conf.GetString("server.credentials.ak"))
	infra.SvrSK = infra.Conf.GetString("server.credentials.sk")

	infra.SDAddrs = infra.Conf.GetStringSlice("sd.addrs")
	infra.RegisterName = infra.Conf.GetString("sd.name")
	infra.SdAK = strings.ToLower(infra.Conf.GetString("sd.credentials.ak"))
	infra.SdSK = infra.Conf.GetString("sd.credentials.sk")

	infra.HubAK = strings.ToLower(infra.Conf.GetString("hub.credentials.ak"))
	infra.HubSK = infra.Conf.GetString("hub.credentials.sk")

	// for hub plugin namespace
	infra.HubPluginNs = infra.Conf.GetString("hub.plugin_ns")

	infra.AgentName = infra.Conf.GetString("agent.name")
	if infra.AgentName == "" {
		infra.AgentName = "elkeid-agent"
	}

	return nil
}
func initTos() {
	// init tos
	var url []string
	if len(monitor.Config.Nginx.SSHHost) != 0 {
		url = append(url, fmt.Sprintf("http://%s", net.JoinHostPort(monitor.Config.Nginx.SSHHost[0].Host, "8080")))
	} else {
		url = append(url, fmt.Sprintf("http://%s", net.JoinHostPort("0.0.0.0", "8080")))
	}
	for _, u := range monitor.Config.Nginx.CdnList {
		url = append(url, u)
	}
	nginxClient, err := tos.NewNginxClient(monitor.Config.Nginx.UploadAddress, url, "/upload", monitor.Config.Nginx.UploadUser, monitor.Config.Nginx.UploadPassword)
	if err != nil {
		fmt.Println("NEW_TOS_ERROR", err.Error())
		os.Exit(-1)
	}
	infra.TosClients = append(infra.TosClients, nginxClient)
}
func initDistribute() {
	job.LocalHost = fmt.Sprintf("%s:%d", infra.LocalIP, infra.HttpPort)
	job.InitApiMap()

	job.AJF = job.NewApiJobFunc()
	//Collect detailed agent status information and write it into mongodb.
	job.AJF.Register("Server_AgentStat", nil, nil, job.AgentHBRlt)

	//Collect the agent<->server list and write it to redis.
	job.AJF.Register("Server_AgentList", nil, nil, job.AgentListRlt)

	//Agent Task
	job.AJF.Register("Agent_Config", atask.AgentControlDistribute, atask.AgentControlDo, nil)
	job.AJF.Register("Agent_Ctrl", atask.AgentControlDistribute, atask.AgentControlDo, nil)
	job.AJF.Register("Agent_Task", atask.AgentControlDistribute, atask.AgentControlDo, nil)
	job.AJF.Register("Agent_Config_v2", atask.AgentControlDistributeV2, atask.AgentControlDoV2, nil)

	job.JM = job.NewJobManager()
	//cron job init
	job.CM = job.NewCronJobManager()
	job.CM.Add("Server_AgentStat", 180, 120, 300)
	job.CM.Add("Server_AgentList", 120, 120, 180)
	go job.CM.Manage()
}

func initMonitor() error {
	monitor.InitConfig()

	if len(monitor.Config.Nginx.SSHHost) != 0 {
		url := []string{fmt.Sprintf("http://%s", net.JoinHostPort(monitor.Config.Nginx.SSHHost[0].Host, "8080"))}
		if monitor.Config.Nginx.PublicAddr != "" {
			u := fmt.Sprintf("http://%s", net.JoinHostPort(monitor.Config.Nginx.PublicAddr, "8080"))
			if url[0] != u {
				url = append(url, u)
			}
		}
		if monitor.Config.Nginx.Domain != "" {
			u := fmt.Sprintf("http://%s", net.JoinHostPort(monitor.Config.Nginx.Domain, "8080"))
			find := false
			for _, i := range url {
				if i == u {
					find = true
					break
				}
			}
			if !find {
				url = append(url, u)
			}
		}
		for _, u := range monitor.Config.Nginx.CdnList {
			url = append(url, u)
		}
		tosClient, err := tos.NewNginxClient(monitor.Config.Nginx.UploadAddress, url, "/upload", monitor.Config.Nginx.UploadUser, monitor.Config.Nginx.UploadPassword)
		if err != nil {
			fmt.Println("NEW_TOS_ERROR", err.Error())
			return err
		}
		infra.TosClients = append(infra.TosClients, tosClient)
	}
	go func() {
		time.Sleep(time.Minute * 5)
		if monitor.Config.Report.Uid != "" {
			monitor.InitReport()
		}
	}()

	return nil
}
