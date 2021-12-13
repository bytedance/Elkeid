package task

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type hbV2Writer struct {
	queue chan interface{}
}

func (w *hbV2Writer) Init() {
	w.queue = make(chan interface{}, 4096*256)
}

func (w *hbV2Writer) Run() {
	var (
		timer    = time.NewTicker(time.Second * time.Duration(SendTimeWeightSec))
		conn     map[string]interface{}
		count    = 0
		hbWrites []mongo.WriteModel
	)

	ylog.Infof("hbV2Writer", "Run")
	heartbeatClient := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		//SEND_TIME_WEIGHT_SEC秒或者数据量大于SEND_COUNT_WEIGHT 写一次redis
		select {
		case tmp := <-w.queue:
			conn = tmp.(map[string]interface{})
			filter := bson.M{"agent_id": conn["agent_id"]}
			if conn["last_heartbeat_time"] != nil {
				conn["last_heartbeat_time_format"] = time.Unix(int64(conn["last_heartbeat_time"].(float64)), 0).Format("2006-01-02 15:04:05")
			}

			updates := bson.M{"$set": conn,
				"$setOnInsert": bson.M{"first_heartbeat_time": time.Now().Unix(), "first_heartbeat_time_format": time.Now().Format("2006-01-02 15:04:05")}}
			model := mongo.NewUpdateOneModel().
				SetFilter(filter).SetUpdate(updates).SetUpsert(true)
			hbWrites = append(hbWrites, model)
			ylog.Debugf("BulkWrite Info", "agentWrites filter: %#v, updates:%#v", filter, updates)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			if len(hbWrites) > 0 {
				res, err := heartbeatClient.BulkWrite(context.Background(), hbWrites, writeOption)
				if err != nil {
					ylog.Errorf("hbV2Writer_BulkWrite", "hbWrites len %d, error: %s", len(hbWrites), err.Error())
				} else {
					ylog.Debugf("hbV2Writer_BulkWrite", "hbWrites UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
				}
				hbWrites = make([]mongo.WriteModel, 0)
				count = 0
			}
		}

		if count >= SendCountWeight {
			if len(hbWrites) > 0 {
				res, err := heartbeatClient.BulkWrite(context.Background(), hbWrites, writeOption)
				if err != nil {
					ylog.Errorf("hbV2Writer_BulkWrite", "hbWrites len %d, error: %s", len(hbWrites), err.Error())
				} else {
					ylog.Debugf("hbV2Writer_BulkWrite", "hbWrites UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
				}
				hbWrites = make([]mongo.WriteModel, 0)
				count = 0
			}
		}
	}
}

func (w *hbV2Writer) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("hbV2Writer", "channel is full len %d", len(w.queue))
	}
}
