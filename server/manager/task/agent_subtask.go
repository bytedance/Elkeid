package task

import (
	"context"
	"github.com/bytedance/Elkeid/server/manger/infra"
	"github.com/bytedance/Elkeid/server/manger/infra/def"
	"github.com/bytedance/Elkeid/server/manger/infra/ylog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type subTaskWriter struct {
	queue chan interface{}
}

func (w *subTaskWriter) Init() {
	w.queue = make(chan interface{}, 4096*256)
}

func (w *subTaskWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(SendTimeWeightSec))
		task   *def.AgentSubTask
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("subTaskWriter", "Run")
	agentSubTaskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			task = tmp.(*def.AgentSubTask)
			model := mongo.NewInsertOneModel().SetDocument(task)
			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "inserts %#v", task)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("subTaskWriter_BulkWrite", "error:%s len:%s", err.Error(), len(writes))
			} else {
				ylog.Debugf("subTaskWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= SendCountWeight {
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("subTaskWriter_BulkWrite", "error:%s len:%s", err.Error(), len(writes))
			} else {
				ylog.Debugf("subTaskWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *subTaskWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("subTaskWriter", "channel is full len %d", len(w.queue))
	}
}
