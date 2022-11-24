package cronjob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/robfig/cron/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var scheduler = cron.New(cron.WithChain(cron.SkipIfStillRunning(cron.DefaultLogger)))

var mu = &sync.Mutex{}
var m = map[string]cron.EntryID{}

func AddJob(api string, dr time.Duration, job func() bson.M) (err error) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := m[api]; ok {
		return errors.New("job of api: " + api + " already exists")
	}
	cmdWrapper := func() {
		if l, err := infra.DistributedLockWithExpireTime(
			fmt.Sprintf(api+"-%d", int(time.Now().Unix()/(int64(dr.Minutes())*60))),
			time.Minute*time.Duration(int(dr.Minutes()))); err == nil && l {
			res := job()
			if res == nil {
				res = bson.M{}
			}
			res["hostname"], _ = os.Hostname()
			res["entry_id"] = m[api]
			res["update_time"] = time.Now().Unix()
			coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CronjobCollection)
			opts := &options.UpdateOptions{}
			opts.SetUpsert(true)
			_, err := coll.UpdateOne(context.Background(), bson.M{"api": api}, bson.M{"$set": res}, opts)
			if err != nil {
				ylog.Errorf("Cronjob", "Update Error For %s: %v,res: %v", api, err, res)
			}
		}
	}
	if dr == time.Hour*24 {
		m[api], err = scheduler.AddFunc("@daily", cmdWrapper)
	} else {
		m[api], err = scheduler.AddFunc(fmt.Sprintf("@every %dm", int(dr.Minutes())), cmdWrapper)
	}
	if err != nil {
		delete(m, api)
	} else {
		go cmdWrapper()
	}
	return
}
func GetLatestResult(api string) (res bson.M, err error) {
	var ok bool
	mu.Lock()
	_, ok = m[api]
	mu.Unlock()
	if ok {
		coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CronjobCollection)
		res = bson.M{}
		err = coll.FindOne(context.Background(), bson.M{"api": api}).Decode(&res)
		if errors.Is(err, mongo.ErrNoDocuments) {
			err = nil
		}
	} else {
		err = errors.New("api not found")
	}
	return
}
func InitCronjob() {
	initOverView()
	initFingerPrint()
	initAssetCenter()
	go scheduler.Run()
}
