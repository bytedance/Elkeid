package task

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type sysAlertWriter struct {
	queue chan interface{}
}

func (w *sysAlertWriter) Init() {
	w.queue = make(chan interface{}, 4096*256)
}

func (w *sysAlertWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(SendTimeWeightSec))
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("sysAlertWriter", "Run")
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV1)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			model := mongo.NewInsertOneModel().SetDocument(tmp)
			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "inserts %#v", tmp)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("sysAlertWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("sysAlertWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("sysAlertWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("sysAlertWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *sysAlertWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("sysAlertWriter", "channel is full len %d", len(w.queue))
	}
}
