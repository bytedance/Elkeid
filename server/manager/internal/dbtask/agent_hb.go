package dbtask

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type hbWriter struct {
	queue chan interface{}
}

func (w *hbWriter) Init() {
	w.queue = make(chan interface{}, channelSize)
}

func (w *hbWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(SendTimeWeightSec))
		conn   *def.ConnStat
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
			conn = tmp.(*def.ConnStat)

			if conn.AgentInfo != nil {
				agentID, ok := conn.AgentInfo["agent_id"]
				if !ok {
					continue
				}

				filter := bson.M{"agent_id": agentID}
				if lastHBTime, ok := conn.AgentInfo["last_heartbeat_time"]; ok {
					if fLastHBTime, ok := lastHBTime.(float64); ok {
						conn.AgentInfo["last_heartbeat_time_format"] = time.Unix(int64(fLastHBTime), 0).Format("2006-01-02 15:04:05")
					}
				}

				//add plugins Info
				if conn.PluginsInfo != nil {
					conn.AgentInfo["plugins"] = conn.PluginsInfo
				}

				updates := bson.M{"$set": conn.AgentInfo,
					"$setOnInsert": bson.M{"first_heartbeat_time": time.Now().Unix(), "first_heartbeat_time_format": time.Now().Format("2006-01-02 15:04:05")}}
				model := mongo.NewUpdateOneModel().
					SetFilter(filter).SetUpdate(updates).SetUpsert(true)
				writes = append(writes, model)

				ylog.Debugf("BulkWrite Info", "agentWrites filter: %#v, updates:%#v", filter, updates)
				count++
			}

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
