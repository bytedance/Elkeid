package alarm_whitelist

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"os"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/outputer"
)

type WLDeleter struct {
	IDList []string `json:"id_list"`
}

type WLDelResp struct {
	ID   string `json:"id" bson:"id"`
	Code int    `json:"code" bson:"code"`
	Msg  string `json:"msg" bson:"msg"`
}

type WhiteListWithID struct {
	ID        primitive.ObjectID     `bson:"_id"`
	Type      int                    `bson:"type"`
	Filter    []common.FilterContent `bson:"filter"`
	Condition string                 `bson:"condition"`

	InsertTime int64 `bson:"insert_time"`
	UpdateTime int64 `bson:"update_time"`
}

var WLWorker WhiteListWorker
var RaspWLWorker WhiteListWorker
var KubeWLWorker WhiteListWorker
var VirusWLWorker WhiteListWorker

type WLUpdater struct {
	Filter  bson.M
	Updater bson.M
}

type WhiteListWorker struct {
	wlChan         chan *WLUpdater
	wlTableName    string
	alarmTableName string
	alarmEventType int
}

const (
	EventTypeHIDS = iota
	EventTypeRASP
	EventTypeKube
	EventTypeVirus
)

func SendAlarmMsgNotice(alarm_event_type int, msg map[string]interface{}) {
	harmLevel, ok := msg["harm_level"].(string)
	if !ok {
		harmLevel = "high"
	}

	var dm *outputer.DataModel = nil

	switch alarm_event_type {
	case EventTypeHIDS:
		dm = outputer.BuildDataModel(outputer.DataModelHidsAlarm,
			outputer.DataSubModelHidsAlarm,
			outputer.DataTypeInsert,
			harmLevel, nil, msg)
	case EventTypeRASP:
		// check lincense
		dm = outputer.BuildDataModel(outputer.DataModelRaspAlarm,
			outputer.DataSubModelRaspAlarm,
			outputer.DataTypeInsert,
			harmLevel, nil, msg)
	case EventTypeKube:
		// check lincense
		dm = outputer.BuildDataModel(outputer.DataModelKubeAlarm,
			outputer.DataSubModelKubeAlarm,
			outputer.DataTypeInsert,
			harmLevel, nil, msg)
	case EventTypeVirus:
		dm = outputer.BuildDataModel(outputer.DataModelVirusAlarm,
			outputer.DataSubModelVirusAlarm,
			outputer.DataTypeInsert,
			harmLevel, nil, msg)
	}

	outputer.OuterHandler.Add(dm)
}

func (w *WhiteListWorker) Init(white_table_name string, alarm_table_name string, event_type int) {
	w.wlChan = make(chan *WLUpdater, 1024)
	w.wlTableName = white_table_name
	w.alarmTableName = alarm_table_name
	w.alarmEventType = event_type
}

func (w *WhiteListWorker) Add(item *WLUpdater) {
	w.wlChan <- item
}

// TODO 索引优化，限定白名单key范围
func (w *WhiteListWorker) Run() {
	ylog.Infof("WhiteListWorker", "Run now!")

	go w.runChecker()
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(w.alarmTableName)
	var item *WLUpdater
	for {
		select {
		case item = <-w.wlChan:
			ylog.Debugf("wlChan", "Filter:%v, Updater:%v", item.Filter, item.Updater)
			res, err := col.UpdateMany(context.Background(), item.Filter, item.Updater)
			if err != nil {
				ylog.Errorf("WhiteListWorker", "UpdateMany Error %s", err.Error())
			} else {
				ylog.Debugf("WhiteListWorker", "res.ModifiedCount %d, res.MatchedCount %d, res.UpsertedCount %d", res.ModifiedCount, res.MatchedCount, res.UpsertedCount)
			}
		}
	}
}

func (w *WhiteListWorker) runChecker() {
	ylog.Infof("WhiteListChecker", "Run now!")
	alarmColOld := infra.MongoClient.Database(infra.MongoDatabase).Collection(w.alarmTableName)
	wlCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(w.wlTableName)
	ticker := time.NewTicker(5 * time.Second)
	checker := fmt.Sprintf("%s:%d", infra.LocalIP, infra.HttpPort)
	ylog.Infof("WhiteListChecker", "checker %s", checker)

	//需要强制从主读
	opts := &options.CollectionOptions{
		ReadPreference: readpref.PrimaryPreferred(),
	}
	alarmCol, err := alarmColOld.Clone(opts)
	if err != nil {
		ylog.Infof("WhiteListChecker", "db.Clone error %s", err.Error())
		os.Exit(-1)
	}
	for {
		select {
		case <-ticker.C:
			ok, err := infra.DistributedLockWithExpireTime(fmt.Sprintf("WhiteListChecker-%d-%d", time.Now().Unix()/5, w.alarmEventType), 4*time.Second)
			if err != nil {
				ylog.Errorf("WhiteListChecker", "DistributedLock error %s", err.Error())
				continue
			}
			if !ok {
				continue
			}

			//TODO tob checkip
			cRes, err := alarmCol.UpdateMany(context.Background(), bson.M{"__checked": false, "__checker": ""},
				bson.M{"$set": bson.M{"__checker": checker}})
			if err != nil {
				ylog.Errorf("WhiteListChecker", "alarmCol.UpdateMany error %s", err.Error())
				continue
			}
			if cRes.ModifiedCount == 0 {
				continue
			}
			ylog.Debugf("WhiteListChecker", "alarmCol.UpdateMany %#v", cRes)

			wls := make([]WhiteListWithID, 0, 50)
			cur, err := wlCol.Find(context.Background(), bson.M{})
			if err != nil {
				ylog.Errorf("WhiteListChecker", err.Error())
				continue
			}
			err = cur.All(context.Background(), &wls)
			if err != nil {
				ylog.Errorf("WhiteListChecker", err.Error())
				continue
			}

			for _, v := range wls {
				tmp := common.FilterQuery{Filter: v.Filter, Condition: v.Condition}
				filter := bson.M{"$and": bson.A{bson.M{"__checked": false, "__checker": checker}, tmp.Transform()}}

				test11, _ := json.Marshal(filter)
				ylog.Debugf("runChecker", "Filter:%s", string(test11))
				res, err := alarmCol.UpdateMany(context.Background(), filter,
					bson.M{"$set": bson.M{"__hit_wl": true}, "$addToSet": bson.M{"__wl": v.ID}})

				if err != nil {
					ylog.Errorf("WhiteListChecker", err.Error())
				} else {
					ylog.Debugf("WhiteListChecker", "res.ModifiedCount %d, res.MatchedCount %d, res.UpsertedCount %d", res.ModifiedCount, res.MatchedCount, res.UpsertedCount)
				}
			}

			//c, _ = alarmCol.CountDocuments(context.Background(), bson.M{"__checked": false, "__checker": checker, "__hit_wl": false})
			//ylog.Infof("WhiteListChecker", "2222 alarmCol.CountDocuments %d", c)
			//告警在过完白名单后，异步追加事件
			cur, err = alarmCol.Find(context.Background(), bson.M{"__checked": false, "__checker": checker, "__hit_wl": false})
			if err != nil {
				ylog.Errorf("WhiteListChecker", "alarmCol.Find Error %s, fail to add alarm to event", err.Error())
				continue
			}
			alarmList := make([]map[string]interface{}, 0, 10)
			err = cur.All(context.Background(), &alarmList)
			if err != nil {
				ylog.Errorf("WhiteListChecker", "alarmCol.Find All Error %s, fail to add alarm to event", err.Error())
				continue
			}

			ylog.Debugf("WhiteListChecker", "len of alarmList %d", len(alarmList))
			for k := range alarmList {
				err = registryData(alarmList[k], w.alarmEventType)
				if err != nil {
					ylog.Debugf("WhiteListChecker", "registryData error %s", err.Error())
				}
			}

			//update
			cRes, err = alarmCol.UpdateMany(context.Background(), bson.M{"__checked": false, "__checker": checker},
				bson.M{"$set": bson.M{"__checked": true, "__update_time": time.Now().Unix()}})
			if err != nil {
				ylog.Errorf("WhiteListChecker", "alarmCol.UpdateMany Error %s", err.Error())
			}
			ylog.Debugf("WhiteListChecker", "last alarmCol.UpdateMany %#v", cRes)
		}
	}
}

// 订阅告警数据
func registryData(data map[string]interface{}, alarmType int) error {
	// 发送告警通知
	SendAlarmMsgNotice(alarmType, data)
	return nil
}
