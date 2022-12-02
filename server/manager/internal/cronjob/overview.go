package cronjob

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
)

type DescribeAgentData struct {
	Running     int64   `json:"running" bson:"running"`
	Offline     int64   `json:"offline" bson:"offline"`
	Memory      int64   `json:"memory" bson:"memory,truncate"`
	CPU         float64 `json:"cpu" bson:"cpu"`
	RunningDiff int64   `json:"running_diff" bson:"running_diff"`
	OfflineDiff int64   `json:"offline_diff" bson:"offline_diff"`
	MemoryDiff  int64   `json:"memory_diff" bson:"memory_diff,truncate"`
	CPUDiff     float64 `json:"cpu_diff" bson:"cpu_diff"`
}

func initOverView() {
	err := AddJob("/api/v6/overview/DescribeAgent", time.Hour*time.Duration(24), func() bson.M {
		data := DescribeAgentData{}
		c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		data.Running, _ = c.CountDocuments(context.Background(), Status2Cond("running"))
		data.Offline, _ = c.CountDocuments(context.Background(), Status2Cond("offline"))
		cursor, err := c.Aggregate(context.Background(), bson.A{
			bson.M{
				"$match": Status2Cond("running"),
			},
			bson.M{
				"$group": bson.M{
					"_id":    "",
					"cpu":    bson.M{"$avg": "$cpu"},
					"memory": bson.M{"$avg": "$rss"},
				},
			},
		})
		if err != nil {
			ylog.Errorf("[Cronjob]", "/api/v6/overview/DescribeAgent: %v", err.Error())
			res := bson.M{}
			content, _ := bson.Marshal(data)
			_ = bson.Unmarshal(content, &res)
			return res
		}
		for cursor.Next(context.Background()) {
			err = cursor.Decode(&data)
			if err != nil {
				ylog.Errorf("[Cronjob]", "/api/v6/overview/DescribeAgent: %v", err.Error())
			}
		}
		oldRes, err := GetLatestResult("/api/v6/overview/DescribeAgent")
		if err == nil && len(oldRes) != 0 {
			content, _ := bson.Marshal(oldRes)
			oldData := DescribeAgentData{}
			_ = bson.Unmarshal(content, &oldData)
			data.CPUDiff = data.CPU - oldData.CPU
			data.MemoryDiff = data.Memory - oldData.Memory
			data.RunningDiff = data.Running - oldData.Running
			data.OfflineDiff = data.Offline - oldData.Offline
		}
		res := bson.M{}
		content, _ := bson.Marshal(data)
		_ = bson.Unmarshal(content, &res)
		return res
	})
	if err != nil {
		ylog.Errorf("initOverView", "AddJob error %s", err.Error())
	}
	err = AddJob("/api/v6/overview/DescribeAsset", time.Minute*5, func() bson.M {
		m := bson.M{
			"host":             0,
			"cluster":          0,
			"container":        0,
			"injected_process": 0,
		}
		coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		var err error
		m["host"], err = coll.CountDocuments(context.Background(), bson.M{})
		if err != nil {
			ylog.Errorf("[Cronjob]", "/api/v6/overview/DescribeAsset: %v", err.Error())
			return m
		}
		coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
		m["cluster"], err = coll.CountDocuments(context.Background(), bson.M{})
		if err != nil {
			ylog.Errorf("[Cronjob]", "/api/v6/overview/DescribeAsset: %v", err.Error())
			return m
		}
		coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentContainerInfoCollection)
		m["container"], err = coll.CountDocuments(context.Background(), bson.M{})
		if err != nil {
			ylog.Errorf("[Cronjob]", "/api/v6/overview/DescribeAsset: %v", err.Error())
			return m
		}
		coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintRaspCollection)
		m["injected_process"], err = coll.CountDocuments(context.Background(), bson.M{"trace_state": "ATTACHED"})
		if err != nil {
			ylog.Errorf("[Cronjob]", "/api/v6/overview/DescribeAsset: %v", err.Error())
		}
		return m
	})
	if err != nil {
		ylog.Errorf("initOverView", "AddJob error %s", err.Error())
	}
}
