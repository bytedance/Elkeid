package dbtask

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	fieldSeq = "package_seq"
	dbName   = "agent_asset_%s"
)

var dtList = []string{"5050", "5051", "5052", "5053", "5054", "5055", "5056", "5057", "5058", "5059", "5060", "5061", "5062", "5063", "5064", "5065"}

type hubAssetWriter struct {
	queue       chan interface{}
	workerQueue map[string]chan interface{}  //datatype --> chan
	seqCache    map[string]map[string]string //datatype --> agentID --> fieldSeq

	commCache *map[string]bool //map指针
}

type CheckSumRes struct {
	CheckSum string `json:"checksum" bson:"checksum"`
}

func (w *hubAssetWriter) Init() {
	w.queue = make(chan interface{}, channelSize)
	w.seqCache = make(map[string]map[string]string, len(dtList))
	w.workerQueue = make(map[string]chan interface{}, len(dtList))
	tmp := make(map[string]bool, 1024)
	w.commCache = &tmp

	for _, v := range dtList {
		w.workerQueue[v] = make(chan interface{}, channelSize)
	}

	for _, v := range dtList {
		w.seqCache[v] = make(map[string]string, 200)
	}

	//常见不常见进程
	w.updateCommCache()
	tk := time.NewTicker(time.Hour)
	go func() {
		for {
			select {
			case <-tk.C:
				w.updateCommCache()
			}
		}
	}()
}

func (w *hubAssetWriter) updateCommCache() {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BinaryControlChecksumResultCollection)
	cur, err := col.Find(context.Background(), bson.M{})
	if err != nil {
		ylog.Errorf("hubAssetWriter_updateCommCache", "Find Error %s", err.Error())
		return
	}

	cache := make(map[string]bool, len(*w.commCache))
	for cur.Next(context.Background()) {
		c := &CheckSumRes{}
		err = cur.Decode(c)
		if err != nil {
			ylog.Errorf("hubAssetWriter_updateCommCache", "Decode Error %s", err.Error())
			continue
		}
		cache[c.CheckSum] = true
	}
	//TODO 可能会导致问题
	//为了性能，不加锁
	w.commCache = &cache
	return
}

func (w *hubAssetWriter) Run() {
	var (
		item  map[string]interface{}
		queue chan interface{}
	)

	//开启指定类型数据消费者
	for k := range w.workerQueue {
		go w.WriterRun(k)
	}

	//run main
	ylog.Infof("hubAssetWriter", "Run main")
	for {
		select {
		case tmp := <-w.queue:
			item = tmp.(map[string]interface{})
			dT, ok := item["data_type"].(string)
			if !ok {
				continue
			}

			if queue, ok = w.workerQueue[dT]; ok {
				select {
				case queue <- item:
				default:
					ylog.Errorf("hubAssetWriter", "%s channel is full len %d", dT, len(w.queue))
				}
			} else {
				ylog.Errorf("hubAssetWriter", "%s channel not found", dT)
			}
		}
	}
}

func (w *hubAssetWriter) WriterRun(dt string) {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(5))
		item   map[string]interface{}
		count  = 0
		writes []mongo.WriteModel
	)

	dbName := fmt.Sprintf(dbName, dt)
	queue := w.workerQueue[dt]

	ylog.Infof("hubAssetWriter", "Run worker %s now", dbName)
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(dbName)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)

	for {
		select {
		case tmp := <-queue:
			item = tmp.(map[string]interface{})
			if dt == "2997" {
				ylog.Infof("BulkWrite_WriterRun", "inserts %#v", tmp)
			}
			seq, ok := item[fieldSeq].(string)
			if !ok {
				continue
			}
			agentID, ok := item["agent_id"].(string)
			if !ok {
				continue
			}
			if tmp, ok := item["in_ipv4_list"].(string); ok && tmp != "" {
				item["intranet_ipv4"] = strings.Split(tmp, ",")
			} else {
				item["intranet_ipv4"] = []string{}
			}

			if tmp, ok := item["in_ipv6_list"].(string); ok && tmp != "" {
				item["intranet_ipv6"] = strings.Split(tmp, ",")
			} else {
				item["intranet_ipv6"] = []string{}
			}

			if tmp, ok := item["ex_ipv4_list"].(string); ok && tmp != "" {
				item["extranet_ipv4"] = strings.Split(tmp, ",")
			} else {
				item["extranet_ipv4"] = []string{}
			}

			if tmp, ok := item["ex_ipv6_list"].(string); ok && tmp != "" {
				item["extranet_ipv6"] = strings.Split(tmp, ",")
			} else {
				item["extranet_ipv6"] = []string{}
			}

			delete(item, "in_ipv4_list")
			delete(item, "in_ipv6_list")
			delete(item, "ex_ipv4_list")
			delete(item, "ex_ipv6_list")

			//string to int
			if tmp, ok := item["start_time"].(string); ok {
				pI, _ := strconv.ParseInt(tmp, 10, 64)
				item["start_time"] = pI
			}
			if tmp, ok := item["last_login_time"].(string); ok {
				pI, _ := strconv.ParseInt(tmp, 10, 64)
				item["last_login_time"] = pI
			}
			if tmp, ok := item["modify_time"].(string); ok {
				pI, _ := strconv.ParseInt(tmp, 10, 64)
				item["modify_time"] = pI
			}
			if tmp, ok := item["create_time"].(string); ok {
				pI, _ := strconv.ParseInt(tmp, 10, 64)
				item["create_time"] = pI
			}

			//
			if dt == "5050" {
				item["common"] = false
				if cs, ok := item["checksum"].(string); ok {
					if _, ok = (*w.commCache)[cs]; ok {
						item["common"] = true
					}
				}
			}

			if w.seqCache[dt][agentID] != seq {
				//清空旧数据(所有seq不相等的)
				_, err := col.DeleteMany(context.Background(), bson.M{"agent_id": agentID, fieldSeq: bson.M{"$ne": seq}})
				if err != nil {
					ylog.Errorf("hubAssetWriter", "%s, %s, %s, DeleteMany %s", agentID, seq, dbName, err.Error())
				}
				w.seqCache[dt][agentID] = seq
			}

			item["update_time"] = time.Now().Unix()
			model := mongo.NewInsertOneModel().SetDocument(item)
			writes = append(writes, model)
			ylog.Debugf("BulkWrite Info", "inserts %#v", item)
			count++
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("hubAssetWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("hubAssetWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := col.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("hubAssetWriter_BulkWrite", "%s, error:%s len:%d", dbName, err.Error(), len(writes))
			} else {
				ylog.Debugf("hubAssetWriter_BulkWrite", "%s, UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", dbName, res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *hubAssetWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("hubAssetWriter", "main channel is full len %d", len(w.queue))
	}
}
