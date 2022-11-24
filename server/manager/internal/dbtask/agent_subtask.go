package dbtask

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type subTaskWriter struct {
	queue chan interface{}
}

func (w *subTaskWriter) Init() {
	w.queue = make(chan interface{}, channelSize)
}

func (w *subTaskWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(2))
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
			model := mongo.NewInsertOneModel().SetDocument(tmp)
			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "inserts %#v", tmp)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("subTaskWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("subTaskWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= SendCountWeight {
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("subTaskWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
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
