package dbtask

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type raspAlarmWriter struct {
	queue chan interface{}
}

func (w *raspAlarmWriter) Init() {
	w.queue = make(chan interface{}, channelSize)
}

func (w *raspAlarmWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(5))
		item   map[string]interface{}
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("raspAlarmWriter", "Run")
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspAlarmCollectionV1)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			item = tmp.(map[string]interface{})
			model := mongo.NewInsertOneModel().SetDocument(item)
			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "inserts %#v", item)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("raspAlarmWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("raspAlarmWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("raspAlarmWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("raspAlarmWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *raspAlarmWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("raspAlarmWriter", "channel is full len %d", len(w.queue))
	}
}
