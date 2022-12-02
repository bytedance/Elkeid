package cronjob

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"go.mongodb.org/mongo-driver/bson"
)

func Status2Cond(status string) (cond bson.M) {
	current := time.Now().Unix()
	switch status {
	case "running":
		cond = bson.M{"last_heartbeat_time": bson.M{"$gte": current - asset_center.DEFAULT_OFFLINE_DURATION}, "state": bson.M{"$ne": "abnormal"}}
	case "abnormal":
		cond = bson.M{"last_heartbeat_time": bson.M{"$gte": current - asset_center.DEFAULT_OFFLINE_DURATION}, "state": "abnormal"}
	case "offline":
		cond = bson.M{"last_heartbeat_time": bson.M{"$lt": current - asset_center.DEFAULT_OFFLINE_DURATION}}
	default:
		cond = bson.M{"last_heartbeat_time": cond}
	}
	return
}

func initAssetCenter() {
	err := AddJob("/api/v6/asset-center/DescribeHostStatistics", time.Minute*time.Duration(10), func() (res bson.M) {
		res = bson.M{
			"total":      0,
			"running":    0,
			"offline":    0,
			"abnormal":   0,
			"vulnerable": 0,
			"baseline":   0,
			"alerted":    0,
		}
		c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		var err error
		res["total"], err = c.CountDocuments(context.Background(), bson.M{"agent_id": bson.M{"$exists": true}})
		if err != nil {
			return
		}
		res["running"], _ = c.CountDocuments(context.Background(), Status2Cond("running"))
		res["abnormal"], _ = c.CountDocuments(context.Background(), Status2Cond("abnormal"))
		res["offline"], _ = c.CountDocuments(context.Background(), Status2Cond("offline"))
		cursor, err := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo).Aggregate(context.Background(), bson.A{
			bson.M{
				"$match": bson.M{
					"status":      "unprocessed",
					"drop_status": "using",
				},
			},
			bson.M{
				"$sort": bson.M{
					"agent_id": 1,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$agent_id",
				},
			},
			bson.M{
				"$lookup": bson.M{
					"from":         infra.AgentHeartBeatCollection,
					"localField":   "_id",
					"foreignField": "agent_id",
					"as":           "hb",
				},
			},
			bson.M{
				"$match": bson.M{
					"hb": bson.M{"$size": 1},
				},
			},
			bson.M{
				"$count": "count",
			},
		})
		if err == nil && cursor.TryNext(context.Background()) {
			cursor.Next(context.Background())
			res["vulnerable"] = cursor.Current.Lookup("count").AsInt64()
		}
		cursor, err = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl).Aggregate(context.Background(), bson.A{
			bson.M{
				"$match": bson.M{
					"status":   "failed",
					"if_white": false,
				},
			}, bson.M{
				"$sort": bson.M{
					"agent_id": 1,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$agent_id",
				},
			},
			bson.M{
				"$lookup": bson.M{
					"from":         infra.AgentHeartBeatCollection,
					"localField":   "_id",
					"foreignField": "agent_id",
					"as":           "hb",
				},
			},
			bson.M{
				"$match": bson.M{
					"hb": bson.M{"$size": 1},
				},
			},
			bson.M{
				"$count": "count",
			},
		})
		if err == nil && cursor.TryNext(context.Background()) {
			cursor.Next(context.Background())
			res["baseline"] = cursor.Current.Lookup("count").AsInt64()
		}
		cursor, err = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1).Aggregate(context.Background(), bson.A{
			bson.M{
				"$match": bson.M{
					"__alarm_status": 0,
					"__checked":      true,
					"__hit_wl":       false,
				},
			},
			bson.M{
				"$sort": bson.M{
					"agent_id": 1,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$agent_id",
				},
			},
			bson.M{
				"$lookup": bson.M{
					"from":         infra.AgentHeartBeatCollection,
					"localField":   "_id",
					"foreignField": "agent_id",
					"as":           "hb",
				},
			},
			bson.M{
				"$match": bson.M{
					"hb": bson.M{"$size": 1},
				},
			},
			bson.M{
				"$count": "count",
			},
		})
		if err == nil && cursor.TryNext(context.Background()) {
			cursor.Next(context.Background())
			res["alerted"] = cursor.Current.Lookup("count").AsInt64()
		}
		return
	})
	if err != nil {
		ylog.Errorf("initAssetCenter", "AddJob error %s", err.Error())
	}
}
