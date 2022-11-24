package cronjob

import (
	"context"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
)

func initFingerPrint() {
	err := AddJob("/api/v6/fingerprint/DescribeTop5", time.Minute*time.Duration(30), func() bson.M {
		res := bson.M{}
		m := sync.Mutex{}
		wg := &sync.WaitGroup{}
		for _, t := range []string{"process", "port", "service", "software", "kmod", "app"} {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.LookupCollection(t))
				items, err := common.CountTop(context.Background(), collection, infra.LookupGroupKey(t), 5)
				if err == nil {
					m.Lock()
					res[t] = items
					m.Unlock()
				} else {
					ylog.Errorf("Cronjob:/api/v6/fingerprint/DescribeTop5", "Group Count %v Error %v", t, err)
				}
			}(t)
		}
		wg.Wait()
		return res
	})
	if err != nil {
		ylog.Errorf("initFingerPrint", "AddJob error %s", err.Error())
	}
	err = AddJob("/api/v6/asset-center/fingerprint/DescribeStatistics", time.Minute*5, func() bson.M {
		res := bson.M{
			"port":      0,
			"process":   0,
			"user":      0,
			"crontab":   0,
			"service":   0,
			"software":  0,
			"container": 0,
			"integrity": 0,
			"app":       0,
		}
		cls := []string{infra.FingerprintPortCollection,
			infra.FingerprintProcessCollection,
			infra.FingerprintUserCollection,
			infra.FingerprintCrontabCollection,
			infra.FingerprintServiceCollection,
			infra.FingerprintSoftwareCollection,
			infra.FingerprintContainerCollection,
			infra.FingerprintIntegrityCollection,
			infra.FingerprintKmodCollection,
			infra.FingerprintAppCollection}
		for i, n := range cls {
			collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(n)
			v, err := collection.CountDocuments(context.Background(), bson.M{})
			if err != nil {
				ylog.Errorf("Cronjob:/api/v6/fingerprint/DescribeStatistics", "Group Count %v Error %v", i, err.Error())
				continue
			}
			switch i {
			case 0:
				res["port"] = v
			case 1:
				res["process"] = v
			case 2:
				res["user"] = v
			case 3:
				res["cron"] = v
			case 4:
				res["service"] = v
			case 5:
				res["software"] = v
			case 6:
				res["container"] = v
			case 7:
				res["integrity"] = v
			case 8:
				res["kmod"] = v
			case 9:
				res["app"] = v
			}
		}
		return res
	})
	if err != nil {
		ylog.Errorf("initFingerPrint", "AddJob error %s", err.Error())
	}
}
