package dbtask

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type virusDetectionWriter struct {
	queue chan interface{}
}

func (w *virusDetectionWriter) Init() {
	w.queue = make(chan interface{}, channelSize)
}

func (w *virusDetectionWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(5))
		item   map[string]interface{}
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("virusDetectionWriter", "Run")
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VirusDetectionCollectionV1)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			item = tmp.(map[string]interface{})
			model := mongo.NewInsertOneModel().SetDocument(item)
			writes = append(writes, model)
			ylog.Debugf("virusDetectionWriter Info", "inserts %#v", item)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("virusDetectionWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("virusDetectionWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("virusDetectionWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("virusDetectionWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *virusDetectionWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("virusDetectionWriter", "channel is full len %d", len(w.queue))
	}
}
