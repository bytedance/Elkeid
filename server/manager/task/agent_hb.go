package task

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type hbWriter struct {
	queue chan interface{}
}

func (w *hbWriter) Init() {
	w.queue = make(chan interface{}, 4096*256)
}

func (w *hbWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(SendTimeWeightSec))
		conn   *def.AgentHBInfo
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("hbWriter", "Run")
	heartbeatClient := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		//SEND_TIME_WEIGHT_SEC秒或者数据量大于SEND_COUNT_WEIGHT 写一次redis
		select {
		case tmp := <-w.queue:
			conn = tmp.(*def.AgentHBInfo)
			filter := bson.M{"agent_id": conn.AgentId}
			setter := bson.M{"cpu": conn.Cpu, "memory": conn.Memory, "net_type": conn.NetType, "addr": conn.Addr,
				"last_heartbeat_time": conn.LastHeartbeatTime, "version": conn.Version, "hostname": conn.HostName,
				"intranet_ipv4": conn.IntranetIPv4, "intranet_ipv6": conn.IntranetIPv6,
				"extranet_ipv4": conn.ExtranetIPv4, "extranet_ipv6": conn.ExtranetIPv6,
				"io": conn.IO, "plugins": conn.Plugin, "slab": conn.Slab,
				"last_heartbeat_time_format": time.Unix(conn.LastHeartbeatTime, 0).Format("2006-01-02 15:04:05"),
				"source_ip":                  conn.SourceIp, "source_port": conn.SourcePort}
			if conn.ConfigUpdateTime != 0 {
				setter["config_update_time"] = conn.ConfigUpdateTime
				setter["config"] = conn.Config
			}
			updates := bson.M{"$set": setter,
				"$setOnInsert": bson.M{"first_heartbeat_time": time.Now().Unix(), "first_heartbeat_time_format": time.Now().Format("2006-01-02 15:04:05")}}
			model := mongo.NewUpdateOneModel().
				SetFilter(filter).SetUpdate(updates).SetUpsert(true)
			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "filter: %#v, updates:%#v", filter, updates)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := heartbeatClient.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("hbWriter_BulkWrite", "len %d, error: %s", len(writes), err.Error())
			} else {
				ylog.Debugf("hbWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= SendCountWeight {
			res, err := heartbeatClient.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("hbWriter_BulkWrite", "len %d, error: %s", len(writes), err.Error())
			} else {
				ylog.Debugf("hbWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *hbWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("hbWriter", "channel is full len %d", len(w.queue))
	}
}
