package metrics

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"github.com/levigross/grequests"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

const (
	MonitorServiceHeartbeatCollection = "monitor_service_heartbeat"
)

type BuildVersion struct {
	Version string `json:"version" bson:"version"`
	Commit  string `json:"commit" bson:"commit"`
	Build   string `json:"build" bson:"build"`
	CI      string `json:"ci" bson:"ci"`
}

func GetHeartbeatFromServiceHeartbeat(ctx context.Context, info monitor.ServiceInfo) ([]MonitorServiceHeartbeat, error) {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(MonitorServiceHeartbeatCollection)
	cursor, err := col.Find(ctx, bson.M{"service_id": info.ID, "service_name": info.Name})
	if err != nil {
		return nil, fmt.Errorf("mongodb find service heartbeat error: %w", err)
	}
	ret := make([]MonitorServiceHeartbeat, 0)
	err = cursor.All(ctx, &ret)
	if err != nil {
		return nil, fmt.Errorf("mongodb service heartbeat cursor all error: %w", err)
	}
	return ret, nil
}

func getVersionByPingAPI(ctx context.Context, url string) (version BuildVersion, err error) {
	opts := grequests.RequestOptions{
		InsecureSkipVerify: true,
		Context:            ctx,
	}

	var resp *grequests.Response
	resp, err = grequests.Get(url+"/ping", &opts)
	if err != nil {
		return version, fmt.Errorf("get ping api error: %w", err)
	}
	err = resp.JSON(&version)
	if err != nil {
		return version, fmt.Errorf("json decode ping api resp error: %w", err)
	} else {
		return version, nil
	}
}

type MonitorServiceHeartbeat struct {
	ServiceID     string    `json:"service_id" bson:"service_id"`
	ServiceName   string    `json:"service_name" bson:"service_name"`
	Instance      string    `json:"instance"`
	LastHeartbeat int64     `json:"last_heartbeat" bson:"last_heartbeat"`
	Status        string    `json:"status" bson:"status"`
	Version       string    `json:"version" bson:"version"`
	Commit        string    `json:"commit" bson:"commit"`
	Build         string    `json:"build" bson:"build"`
	CI            string    `json:"ci" bson:"ci"`
	UpdateAt      time.Time `json:"update_at" bson:"update_at"`
}

func runMonitorServiceHeartbeat() {
	defer func() {
		if r := recover(); r != nil {
			ylog.Errorf("ServiceHeartbeat", fmt.Sprint(r))
		}
	}()

	ctx := context.Background()
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(MonitorServiceHeartbeatCollection)
	writes := make([]mongo.WriteModel, 0)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)

	for _, service := range []monitor.ServiceInfo{monitor.ServiceHub, monitor.ServiceLeader, monitor.ServiceManager} {
		instances := monitor.GetServiceAllAddress(service.Name)
		for _, instance := range instances {
			version, err := getVersionByPingAPI(ctx, instance)
			if err != nil {
				ylog.Errorf("MonitorServiceHeartbeat", err.Error())
				continue
			}
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"instance": instance}).
				SetUpdate(bson.M{"$set": MonitorServiceHeartbeat{
					ServiceID:     service.ID,
					ServiceName:   service.Name,
					Instance:      instance,
					LastHeartbeat: time.Now().Unix(),
					Status:        "Running",
					Version:       version.Version,
					Commit:        version.Commit,
					Build:         version.Build,
					CI:            version.CI,
					UpdateAt:      time.Now(),
				}}).
				SetUpsert(true)
			writes = append(writes, model)
		}
	}

	if len(writes) > 0 {
		_, err := col.BulkWrite(ctx, writes, writeOption)
		if err != nil {
			ylog.Errorf("MonitorServiceHeartbeat", "bulk write err: "+err.Error())
		}
	}
}
