package task

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

const sendTimeWeightSec = 5

type subTaskUpdateWriter struct {
	queue chan interface{}
}

func (w *subTaskUpdateWriter) Init() {
	w.queue = make(chan interface{}, 4096*256)
}

func (w *subTaskUpdateWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(sendTimeWeightSec))
		item   map[string]interface{}
		count  = 0
		writes []mongo.WriteModel
		filter bson.M
	)

	ylog.Infof("subTaskUpdateWriter", "Run")
	agentSubTaskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			//filter first task_id+agent_id, then token
			item = tmp.(map[string]interface{})
			taskID, ok1 := item["task_id"]
			agentID, ok2 := item["agent_id"]
			token, ok3 := item["token"]
			if ok1 && ok2 {
				//filter set task_id+agent_id
				filter = bson.M{"task_id": taskID, "agent_id": agentID}
			} else if ok3 {
				//filter set token
				filter = bson.M{"token": token}
			} else {
				continue
			}

			item["update_time"] = time.Now().Unix()
			updates := bson.M{"$set": item}
			model := mongo.NewUpdateOneModel().
				SetFilter(filter).SetUpdate(updates).SetUpsert(true)
			writes = append(writes, model)
			ylog.Debugf("subTaskUpdateWriter_BulkWrite Info", "filter %#v; updates %#v", filter, updates)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("subTaskUpdateWriter_BulkWrite", "error:%s len:%s", err.Error(), len(writes))
			} else {
				ylog.Debugf("subTaskUpdateWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= SendCountWeight {
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("subTaskUpdateWriter_BulkWrite", "error:%s len:%s", err.Error(), len(writes))
			} else {
				ylog.Debugf("subTaskUpdateWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *subTaskUpdateWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("subTaskUpdateWriter", "channel is full len %d", len(w.queue))
	}
}
