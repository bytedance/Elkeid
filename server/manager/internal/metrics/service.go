package metrics

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"go.mongodb.org/mongo-driver/bson"
	"sync"
	"time"
)

const (
	ServiceInstanceAlive = "alive"
	ServiceInstanceDead  = "dead"
)

type serviceStatisticsData struct {
	AgentCount  int     `json:"agent_count"`
	AgentAvgCpu float64 `json:"agent_avg_cpu"`
	AgentAvgMem float64 `json:"agent_avg_mem"`

	AcStatus string  `json:"ac_status"`
	AcQps    float64 `json:"ac_qps"`
	AcAvgCpu float64 `json:"ac_avg_cpu"`
	AcAvgMem float64 `json:"ac_avg_mem"`
	AcUsage  int     `json:"-"`

	KafkaStatus string  `json:"kafka_status"`
	KafkaQps    float64 `json:"kafka_qps"`
	KafkaAvgCpu float64 `json:"kafka_avg_cpu"`
	KafkaAvgMem float64 `json:"kafka_avg_mem"`
	KafkaUsage  int     `json:"-"`

	HubStatus string  `json:"hub_status"`
	HubQps    float64 `json:"hub_qps"`
	HubAvgCpu float64 `json:"hub_avg_cpu"`
	HubAvgMem float64 `json:"hub_avg_mem"`
	HubUsage  int     `json:"-"`
}

var ServiceStatistics = serviceStatisticsData{}
var ServiceStatisticsLastUpdate = time.Time{}
var ServiceStatisticsUpdateMutex = &sync.Mutex{}

func getAgentCountFromHeartbeatCol() int {
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	ret, err := collection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		return 0
	}
	return int(ret)
}

func UpdateServiceStatistics() {
	ServiceStatisticsUpdateMutex.Lock()
	defer ServiceStatisticsUpdateMutex.Unlock()
	if time.Now().Sub(ServiceStatisticsLastUpdate) > time.Second*30 {
		defer func() {
			ServiceStatisticsLastUpdate = time.Now()
		}()

		ctx := context.Background()
		ServiceStatistics.AgentCount =
			PromQueryJsonPathWithRetInt(ctx, "elkeid_ac_grpc_conn_count", "$.data.result[0].value.[1]")
		ServiceStatistics.AgentAvgCpu =
			PromQueryJsonPathWithRetFloat(ctx, "avg(sum(elkeid_ac_agent_cpu)by(agent_id))", "$.data.result[0].value.[1]")
		ServiceStatistics.AgentAvgMem =
			PromQueryJsonPathWithRetFloat(ctx, "avg(sum(elkeid_ac_agent_rss)by(agent_id))", "$.data.result[0].value.[1]")

		ServiceStatistics.AcQps =
			PromQueryJsonPathWithRetFloat(ctx, "sum(rate(elkeid_ac_output_count[5m]))", "$.data.result[0].value.[1]")
		ServiceStatistics.AcAvgCpu =
			GetAvgCpuByHosts(ctx, monitor.GetHostsByService(monitor.ServiceAC.Name))
		ServiceStatistics.AcAvgMem =
			GetAvgMemByHosts(ctx, monitor.GetHostsByService(monitor.ServiceAC.Name))

		if ServiceStatistics.AcQps > 0 && ServiceStatistics.AcAvgCpu > 0 && ServiceStatistics.AcAvgMem > 0 {
			ServiceStatistics.AcUsage = int(ServiceStatistics.AcAvgCpu*60 + ServiceStatistics.AcAvgMem*40)
			ServiceStatistics.AcStatus = UsageToStatus(ServiceStatistics.AcUsage)
		} else {
			ServiceStatistics.AcStatus = MonitorServiceUsageUnavailable
		}

		ServiceStatistics.KafkaQps =
			PromQueryJsonPathWithRetFloat(ctx, "sum(rate(kafka_topic_partition_current_offset{topic=~'hids_svr'}[1m]))", "$.data.result[0].value.[1]")
		ServiceStatistics.KafkaAvgCpu =
			GetAvgCpuByHosts(ctx, monitor.GetHostsByService(monitor.ServiceKafka.Name))
		ServiceStatistics.KafkaAvgMem =
			GetAvgMemByHosts(ctx, monitor.GetHostsByService(monitor.ServiceKafka.Name))

		if ServiceStatistics.KafkaQps > 0 && ServiceStatistics.KafkaAvgCpu > 0 && ServiceStatistics.KafkaAvgMem > 0 {
			ServiceStatistics.KafkaUsage = int(ServiceStatistics.KafkaAvgCpu*60 + ServiceStatistics.KafkaAvgMem*40)
			ServiceStatistics.KafkaStatus = UsageToStatus(ServiceStatistics.KafkaUsage)
		} else {
			ServiceStatistics.KafkaStatus = MonitorServiceUsageUnavailable
		}

		ServiceStatistics.HubQps =
			PromQueryJsonPathWithRetFloat(ctx, "sum(rate(elkeid_hub_stream_counter{type='input',id='hids'}[1m]))", "$.data.result[0].value.[1]")
		ServiceStatistics.HubAvgCpu =
			GetAvgCpuByHosts(ctx, monitor.GetHostsByService(monitor.ServiceHub.Name))
		ServiceStatistics.HubAvgMem =
			GetAvgMemByHosts(ctx, monitor.GetHostsByService(monitor.ServiceHub.Name))

		if ServiceStatistics.HubQps > 0 && ServiceStatistics.HubAvgCpu > 0 && ServiceStatistics.HubAvgMem > 0 {
			ServiceStatistics.HubUsage = int(ServiceStatistics.HubAvgCpu*60 + ServiceStatistics.HubAvgMem*40)
			ServiceStatistics.HubStatus = UsageToStatus(ServiceStatistics.HubUsage)
		} else {
			ServiceStatistics.HubStatus = MonitorServiceUsageUnavailable
		}

		// 若心跳表不存在agent记录, 所有服务不会显示未不可用
		if getAgentCountFromHeartbeatCol() == 0 {
			if ServiceStatistics.AcStatus == MonitorServiceUsageUnavailable {
				ServiceStatistics.AcStatus = MonitorServiceUsageLow
			}
			if ServiceStatistics.KafkaStatus == MonitorServiceUsageUnavailable {
				ServiceStatistics.KafkaStatus = MonitorServiceUsageLow
			}
			if ServiceStatistics.HubStatus == MonitorServiceUsageUnavailable {
				ServiceStatistics.HubStatus = MonitorServiceUsageLow
			}
		}
	}
}

type ServiceInstance struct {
	Status        string `json:"status"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	LastHeartbeat int64  `json:"last_heartbeat"`
}

type ServiceInfo struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Version       string            `json:"version"`
	CI            string            `json:"ci"`
	Commit        string            `json:"commit"`
	Build         string            `json:"build"`
	Quota         string            `json:"quota"`
	LastHeartbeat int64             `json:"last_heartbeat"`
	Alive         int               `json:"alive"`
	Sum           int               `json:"sum"`
	Instances     []ServiceInstance `json:"instances"`
}

var ServiceInfoList = make([]ServiceInfo, 0)
var ServiceInfoListLastUpdate = time.Time{}
var ServiceInfoListUpdateMutex = &sync.Mutex{}

func UpdateServiceList() {
	ServiceInfoListUpdateMutex.Lock()
	defer ServiceInfoListUpdateMutex.Unlock()
	if time.Now().Sub(ServiceInfoListLastUpdate) > time.Second*30 {
		defer func() {
			ServiceInfoListLastUpdate = time.Now()
		}()

		ctx := context.Background()
		ServiceInfoList = ServiceInfoList[:0]

		for _, info := range []monitor.ServiceInfo{monitor.ServiceHub, monitor.ServiceLeader, monitor.ServiceManager} {
			heartbeats, err := GetHeartbeatFromServiceHeartbeat(ctx, info)
			if err != nil {
				ylog.Errorf("MonitorServiceListUpdate", "err: "+err.Error())
			}

			service := ServiceInfo{
				ID:          info.ID,
				Name:        info.Name,
				Description: info.Description,
				Sum:         len(heartbeats),
			}
			switch info.Name {
			case monitor.ServiceHub.Name:
				service.Quota = string(monitor.Config.HUB.Quota)
			case monitor.ServiceLeader.Name:
				service.Quota = string(monitor.Config.HubLeader.Quota)
			case monitor.ServiceManager.Name:
				service.Quota = string(monitor.Config.MG.Quota)
			case monitor.ServiceAC.Name:
				service.Quota = string(monitor.Config.AC.Quota)
			case monitor.ServiceKafka.Name:
				service.Quota = string(monitor.Config.Kafka.Quota)
			case monitor.ServiceMongodb.Name:
				service.Quota = string(monitor.Config.Mongodb.Quota)
			case monitor.ServiceRedis.Name:
				service.Quota = string(monitor.Config.Redis.Quota)
			}
			if service.Quota == "" {
				service.Quota = "Unlimited"
			}
			if len(heartbeats) != 0 {
				service.Version = heartbeats[0].Version
				service.Build = heartbeats[0].Build
				service.CI = heartbeats[0].CI
				service.Commit = heartbeats[0].Commit
				for _, heartbeat := range heartbeats {
					instance := ServiceInstance{
						Name:          heartbeat.ServiceName,
						IP:            heartbeat.Instance,
						LastHeartbeat: heartbeat.LastHeartbeat,
					}
					if time.Now().Unix()-heartbeat.LastHeartbeat < 120 {
						service.Alive += 1
						instance.Status = ServiceInstanceAlive
					} else {
						instance.Status = ServiceInstanceDead
						service.LastHeartbeat = instance.LastHeartbeat
					}
					service.Instances = append(service.Instances, instance)
				}
			}
			ServiceInfoList = append(ServiceInfoList, service)
		}
	}
}
