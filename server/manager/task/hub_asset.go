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

type hubAssetWriter struct {
	queue chan interface{}
}

func (w *hubAssetWriter) Init() {
	w.queue = make(chan interface{}, 4096*256)
}

func (w *hubAssetWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(5))
		item   map[string]interface{}
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("hubAssetWriter", "Run")
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			item = tmp.(map[string]interface{})

			agentID, ok := item["agent_id"]
			if !ok {
				continue
			}
			dT, ok := item["data_type"]
			if !ok {
				continue
			}

			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"data_type": dT, "agent_id": agentID}).
				SetUpdate(bson.M{"$set": item}).
				SetUpsert(true)

			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "inserts %#v", item)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("hubAssetWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("hubAssetWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("hubAssetWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("hubAssetWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *hubAssetWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("hubAssetWriter", "channel is full len %d", len(w.queue))
	}
}
