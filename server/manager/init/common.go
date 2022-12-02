package init

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/bytedance/Elkeid/server/manager/internal/alarm"
	"github.com/bytedance/Elkeid/server/manager/internal/alarm_whitelist"
	"github.com/bytedance/Elkeid/server/manager/internal/virus_detection"

	v6 "github.com/bytedance/Elkeid/server/manager/biz/handler/v6"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/kube"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func initAlarmWhitelist() {

	// whitelist worker for hids
	alarm_whitelist.WLWorker.Init(infra.HubWhiteListCollectionV1, infra.HubAlarmCollectionV1, alarm_whitelist.EventTypeHIDS)
	go alarm_whitelist.WLWorker.Run()

	// whitelist worker for rasp
	alarm_whitelist.RaspWLWorker.Init(infra.RaspAlarmWhiteV1, infra.RaspAlarmCollectionV1, alarm_whitelist.EventTypeRASP)
	go alarm_whitelist.RaspWLWorker.Run()

	// whitelist worker for kube
	alarm_whitelist.KubeWLWorker.Init(infra.KubeAlarmWhiteCollectionV1, infra.KubeAlarmCollectionV1, alarm_whitelist.EventTypeKube)
	go alarm_whitelist.KubeWLWorker.Run()

	// whitelist worker for virus
	alarm_whitelist.VirusWLWorker.Init(infra.VirusDetectionWhiteCollectionV1, infra.VirusDetectionCollectionV1, alarm_whitelist.EventTypeVirus)
	go alarm_whitelist.VirusWLWorker.Run()
	alarm.InitAlarm()

	kube.InitKubeSec()

	virus_detection.InitVirusDetection()
}

func initKube() {
	kube.InitCaCert()
	go kube.InitClusterStatus()
}

func initV6() {
	go v6.VulnInit()
	go v6.InitComponent()
}

type indexItem struct {
	Keys   map[string]interface{} `json:"keys"`
	Unique bool                   `json:"unique"`
}

type indexCollection struct {
	CollectionName string      `json:"collection"`
	Index          []indexItem `json:"index"`
}

func initIndexes() {
	indexFile, err := os.Open("./conf/index.json")
	if err != nil {
		ylog.Errorf("initIndexes", "Open File error %s", err.Error())
		return
	}
	defer func() {
		_ = indexFile.Close()
	}()

	var indexCollections []indexCollection
	b, _ := io.ReadAll(indexFile)
	err = json.Unmarshal(b, &indexCollections)
	if err != nil {
		ylog.Errorf("initIndexes", "json.Unmarshal error %s", err.Error())
		return
	}

	for _, c := range indexCollections {
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(c.CollectionName)
		for _, index := range c.Index {
			keys := bson.D{}
			for field, value := range index.Keys {
				keys = append(keys, bson.E{Key: field, Value: int(value.(float64))})
			}
			mod := mongo.IndexModel{
				Keys:    keys,
				Options: options.Index().SetUnique(index.Unique),
			}
			_, err = collection.Indexes().CreateOne(context.Background(), mod)
			if err != nil {
				ylog.Errorf("initIndexes", "CollectionName %s Keys %#v, CreateOne error %s", keys, c.CollectionName, err.Error())
				continue
			}
		}
	}
}
