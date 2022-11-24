package virus_detection

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type VirusScanTaskStatistics struct {
	RunningTaskNum   int   `json:"running_task_num" bson:"running_task_num"`
	FininshedTaskNum int   `json:"finished_task_num" bson:"finished_task_num"`
	LastScanTime     int64 `json:"last_scan_time" bson:"last_scan_time"`
}

type VirusTaskStatAggresData struct {
	Status       string `json:"status" bson:"status"`
	Count        int    `json:"count" bson:"count"`
	LastScanTime int64  `json:"last_scan_time" bson:"last_scan_time"`
}

func UpdateVirusTaskStatistics(c context.Context) {
	var rsp VirusScanTaskStatistics

	matchQuery := bson.D{primitive.E{
		Key: "$match",
		Value: bson.D{primitive.E{
			Key: "action",
			Value: bson.D{primitive.E{
				Key:   "$in",
				Value: VirusTaskActionList,
			}},
		}},
	}}

	groupQuery := bson.D{primitive.E{
		Key: "$group",
		Value: bson.D{
			primitive.E{Key: "_id", Value: "$task_status"},
			primitive.E{Key: "count", Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
			primitive.E{Key: "last_scan_time", Value: bson.D{primitive.E{Key: "$max", Value: "$create_time"}}},
		},
	}}

	projectQuery := bson.D{primitive.E{
		Key: "$project",
		Value: bson.D{
			primitive.E{Key: "status", Value: "$_id"},
			primitive.E{Key: "count", Value: 1},
			primitive.E{Key: "last_scan_time", Value: 1},
		}}}

	pipeline := mongo.Pipeline{
		matchQuery,
		groupQuery,
		projectQuery,
	}

	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	opts := options.Aggregate().SetMaxTime(15 * time.Second)
	cursor, err := collection.Aggregate(context.TODO(), pipeline, opts)
	if err != nil {
		ylog.Errorf("func UpdateVirusTaskStatistics Aggregate run error", err.Error())
		return
	}

	var outList []VirusTaskStatAggresData
	err = cursor.All(c, &outList)
	if err != nil {
		ylog.Errorf("func UpdateVirusTaskStatistics Aggregate decode error", err.Error())
		return
	}

	rsp.LastScanTime = 0
	for _, one := range outList {
		switch one.Status {
		case "running":
			rsp.RunningTaskNum = rsp.RunningTaskNum + one.Count
		case "created":
			rsp.RunningTaskNum = rsp.RunningTaskNum + one.Count
		case "finished":
			rsp.FininshedTaskNum = rsp.FininshedTaskNum + one.Count
		}

		if one.LastScanTime > rsp.LastScanTime {
			rsp.LastScanTime = one.LastScanTime
		}
	}

	// update db
	statCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VirusDetectionTaskStatCollectionV1)
	option := &options.UpdateOptions{}
	option.SetUpsert(true)
	setValue := bson.M{"$set": rsp}
	_, err = statCol.UpdateOne(c, bson.M{}, setValue, option)
	if err != nil {
		ylog.Errorf("func UpdateVirusTaskStatistics update Statistics error", err.Error())
		return
	}

	return
}
