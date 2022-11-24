package dbtask

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/muesli/cache2go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// rasp心跳key数据
type RaspHeartBeat struct {
	Pid        string `json:"pid" bson:"pid"`
	AgentId    string `json:"agent_id" bson:"agent_id"`
	Runtime    string `json:"runtime" bson:"runtime"`
	ExeName    string `json:"exe_name" bson:"exe_name"`
	TraceState string `json:"trace_state" bson:"trace_state"`
}

// rasp探针key数据
type RaspProbeStruct struct {
	Pid     string `json:"pid" bson:"pid"`
	AgentId string `json:"agent_id" bson:"agent_id"`
	Filter  string `json:"filter" bson:"filter"`
	Block   string `json:"block" bson:"block"`
	Limit   string `json:"limit" bson:"limit"`
	Patch   string `json:"patch" bson:"patch"`
}

type RaspConfigRule struct {
	Runtime   string   `json:"runtime" bson:"runtime"`
	HookFunc  []string `json:"hook_func" bson:"hook_func"`
	HookParam int      `json:"hook_param" bson:"hook_param"`
	Rules     []struct {
		Type string `json:"type" bson:"type"`
		Rule string `json:"rule" bson:"rule"`
	} `json:"rules" bson:"rules"`
}
type RaspConfig struct {
	Id         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	User       string             `json:"user" bson:"user"`
	IfProtect  bool               `json:"if_protect" bson:"if_protect"`
	IpList     []string           `json:"ip_list" bson:"ip_list"`
	Tag        string             `json:"tag" bson:"tag"`
	Cmd        string             `json:"cmd" bson:"cmd"`
	EnvList    []string           `json:"env_list" bson:"env_list"`
	AliveTime  int                `json:"alive_time" bson:"alive_time"`
	Runtime    []string           `json:"runtime" bson:"runtime"`
	Block      []RaspConfigRule   `json:"block" bson:"block"`
	Filter     []RaspConfigRule   `json:"filter" bson:"filter"`
	EnvJson    map[string]string  `json:"env_json" bson:"env_json"`
	BlockUuid  string             `json:"block_uuid" bson:"block_uuid"`
	FilterUuid string             `json:"filter_uuid" bson:"filter_uuid"`
	LimitUuid  string             `json:"limit_uuid" bson:"limit_uuid"`
	PatchUuid  string             `json:"patch_uuid" bson:"patch_uuid"`
	TaskStr    string             `json:"task_str" bson:"task_str"`
}

var (
	rasp2997Cache     *cache2go.CacheTable
	rasp2996Cache     *cache2go.CacheTable
	raspCacheTimeout  = 1 * time.Hour
	runtimeConfigList = []string{"Golang", "JVM", "PHP", "CPython", "NodeJS"}
)

const (
	RaspHB2997     = "2997"
	RaspConfig2996 = "2996"
)

// 计算rasp数据hash
func getRaspHash(raspInfo map[string]interface{}, datatype string) (hash string) {
	m := md5.New()
	switch datatype {
	case RaspHB2997:
		agentId, ok1 := raspInfo["agent_id"].(string)
		pid, ok2 := raspInfo["pid"].(string)
		runtime, ok3 := raspInfo["runtime"].(string)
		exeName, ok4 := raspInfo["exe_name"].(string)
		traceState, ok5 := raspInfo["trace_state"].(string)
		if ok1 && ok2 && ok3 && ok4 && ok5 {
			m.Write([]byte(pid + agentId + runtime + exeName + traceState))
		} else {
			return
		}
	case RaspConfig2996:
		agentId, ok1 := raspInfo["agent_id"].(string)
		pid, ok2 := raspInfo["pid"].(string)
		filter, ok3 := raspInfo["filter"].(string)
		block, ok4 := raspInfo["block"].(string)
		limit, ok5 := raspInfo["limit"].(string)
		if ok1 && ok2 && ok3 && ok4 && ok5 {
			m.Write([]byte(agentId + pid + filter + block + limit))
		} else {
			return
		}
	}
	return hex.EncodeToString(m.Sum(nil))
}

// 判断rasp心跳数据是否已存在,返回心跳缓存时间
func checkRaspCache(raspHash string, datatype string) (ifExist bool, cacheValue int64) {
	switch datatype {
	case RaspHB2997:
		cacheItem, err := rasp2997Cache.Value(raspHash)
		if err != nil {
			rasp2997Cache.Add(raspHash, raspCacheTimeout, time.Now().Unix())
			return false, time.Now().Unix()
		} else {
			cacheValue = cacheItem.Data().(int64)
			return true, cacheValue
		}
	case RaspConfig2996:
		cacheItem, err := rasp2996Cache.Value(raspHash)
		if err != nil {
			rasp2996Cache.Add(raspHash, raspCacheTimeout, time.Now().Unix())
			return false, time.Now().Unix()
		} else {
			cacheValue = cacheItem.Data().(int64)
			return true, cacheValue
		}
	default:
		return false, time.Now().Unix()
	}
}

// rasp心跳入mongo
// TODO 如果es前端查询性能OK，这里完全移植至ES
func rasp2Mongo(raspInfo map[string]interface{}) (writeModel mongo.WriteModel, err error) {

	// raspinfo 解析
	agent_id, ok := raspInfo["agent_id"].(string)
	if !ok {
		err = errors.New("no agent_id")
		return
	}

	pid, ok := raspInfo["pid"].(string)
	if !ok {
		err = errors.New("no pid")
		return
	}

	datatype, ok := raspInfo["data_type"].(string)
	if !ok {
		err = errors.New("no pid")
		return
	}

	tag, ok := raspInfo["tags"].(string)
	if ok && tag == "rasp_online" {
		return
	}
	raspHash := getRaspHash(raspInfo, datatype)
	ifExist, cacheTime := checkRaspCache(raspHash, datatype)

	switch datatype {
	case RaspHB2997:
		// 获取主机数量，如果主机数超过5000，改成每小时更新update_time
		var agentNum int64
		var updateCacheTime int64
		res, err := IfLargeAgentCache.Value("if_large_agent")
		if err != nil {
			collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
			agentNum, err = collection.CountDocuments(context.Background(), bson.M{"last_heartbeat_time": bson.M{"$gte": time.Now().Unix() - 600}})
			if err == nil {
				IfLargeAgentCache.Add("if_large_agent", CacheTimeout, agentNum)
			}
		} else {
			agentNum = res.Data().(int64)
		}
		if agentNum >= 5000 {
			updateCacheTime = 3600
		} else {
			updateCacheTime = 300
		}

		// 如果心跳未变动且超过updateCacheTime未更新，更新update_time
		if ifExist && time.Now().Unix()-cacheTime > updateCacheTime {

			writeModel = mongo.NewUpdateOneModel().
				SetFilter(bson.M{"agent_id": agent_id, "pid": pid}).
				SetUpdate(bson.M{"$set": bson.M{"update_time": time.Now().Unix()}})
			return writeModel, err
		}
		// 如果心跳不存在/有变动，插入
		if !ifExist {
			raspInfo["update_time"] = time.Now().Unix()

			if tmp, ok := raspInfo["uptime"].(string); ok {
				raspInfo["uptime"], err = strconv.Atoi(tmp)
				if err != nil {
					raspInfo["uptime"] = err
				}
			}
			if tmp, ok := raspInfo["in_ipv4_list"].(string); ok && tmp != "" {
				raspInfo["intranet_ipv4"] = strings.Split(tmp, ",")
			} else {
				raspInfo["intranet_ipv4"] = []string{}
			}

			if tmp, ok := raspInfo["in_ipv6_list"].(string); ok && tmp != "" {
				raspInfo["intranet_ipv6"] = strings.Split(tmp, ",")
			} else {
				raspInfo["intranet_ipv6"] = []string{}
			}

			if tmp, ok := raspInfo["ex_ipv4_list"].(string); ok && tmp != "" {
				raspInfo["extranet_ipv4"] = strings.Split(tmp, ",")
			} else {
				raspInfo["extranet_ipv4"] = []string{}
			}

			if tmp, ok := raspInfo["ex_ipv6_list"].(string); ok && tmp != "" {
				raspInfo["extranet_ipv6"] = strings.Split(tmp, ",")
			} else {
				raspInfo["extranet_ipv6"] = []string{}
			}
			delete(raspInfo, "in_ipv4_list")
			delete(raspInfo, "in_ipv6_list")
			delete(raspInfo, "ex_ipv4_list")
			delete(raspInfo, "ex_ipv6_list")

			writeModel = mongo.NewUpdateOneModel().
				SetFilter(bson.M{"agent_id": agent_id, "pid": pid}).
				SetUpdate(bson.M{"$set": raspInfo}).
				SetUpsert(true)
			return writeModel, err
		}
	case RaspConfig2996:
		if !ifExist {
			filter, ok1 := raspInfo["filter"].(string)
			block, ok2 := raspInfo["block"].(string)
			limit, ok3 := raspInfo["limit"].(string)
			if ok1 && ok2 && ok3 {
				writeModel = mongo.NewUpdateOneModel().
					SetFilter(bson.M{"agent_id": agent_id, "pid": pid}).
					SetUpdate(bson.M{"$set": bson.M{"filter": filter, "block": block, "limit": limit}})
			}
			return writeModel, err
		}
	}
	return
}

// rasp数据处理
// todo 打点
func dealRaspList(raspData map[string]interface{}) (writeModel mongo.WriteModel, err error) {
	// 筛选当前配置的语言项
	runtime, ok := raspData["runtime"].(string)
	if !ok {
		err = errors.New("no runtime")
		return
	}
	ifRuntime := false
	for _, runtimeC := range runtimeConfigList {
		if runtime == runtimeC {
			ifRuntime = true
			break
		}
	}
	if !ifRuntime {
		return
	}

	// 心跳数据存mongo
	writeModel, err = rasp2Mongo(raspData)
	if err != nil {
		ylog.Errorf("dealRaspList-rasp2Mongo", err.Error())
		return
	}

	return
}

// rasp 2996数据处理
func dealRaspConfigList(raspData map[string]interface{}) (writeModel mongo.WriteModel, err error) {
	// 数据入mongo
	writeModel, err = rasp2Mongo(raspData)

	return
}

type leaderRaspWriter struct {
	queue chan interface{}
}

func (w *leaderRaspWriter) Init() {
	w.queue = make(chan interface{}, channelSize)
	rasp2997Cache = cache2go.Cache("rasp2997Cache")
	IfLargeAgentCache = cache2go.Cache("IfLargeAgentCache")
	rasp2996Cache = cache2go.Cache("rasp2996Cache")
}

func (w *leaderRaspWriter) Run() {
	var (
		timer        = time.NewTicker(time.Second * time.Duration(5))
		cleanTimer   = time.NewTicker(time.Hour * time.Duration(1))
		count        = 0
		raspHbWrites []mongo.WriteModel
	)

	raspHbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintRaspCollection)

	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case tmp := <-w.queue:
			// 根据不同datatype写到不同write
			raspInfo := tmp.(map[string]interface{})
			datatype, ok := raspInfo["data_type"].(string)
			if !ok {
				continue
			}
			switch datatype {
			case RaspHB2997:
				mongoModel, err := dealRaspList(raspInfo)
				if err != nil {
					continue
				}
				if mongoModel != nil {
					raspHbWrites = append(raspHbWrites, mongoModel)
					count++
				}
			case RaspConfig2996:
				mongoModel, err := dealRaspConfigList(raspInfo)
				if err != nil {
					continue
				}
				if mongoModel != nil {
					raspHbWrites = append(raspHbWrites, mongoModel)
					count++
				}

			default:
			}

		// 定时写mongo(5分钟)
		case <-timer.C:
			if count < 1 {
				continue
			}

			res, err := raspHbCol.BulkWrite(context.Background(), raspHbWrites, writeOption)
			if err != nil {
				ylog.Errorf("leaderRaspWriter_BulkWrite", "error:%s len:%s", err.Error(), len(raspHbWrites))
			} else {
				ylog.Debugf("leaderRaspWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			raspHbWrites = make([]mongo.WriteModel, 0)
			count = 0

			// count数量过多，直接写mongo
			if count >= 100 {
				res, err := raspHbCol.BulkWrite(context.Background(), raspHbWrites, writeOption)
				if err != nil {
					ylog.Errorf("leaderRaspWriter_BulkWrite", "error:%s len:%s", err.Error(), len(raspHbWrites))
				} else {
					ylog.Debugf("leaderRaspWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
				}

				raspHbWrites = make([]mongo.WriteModel, 0)
				count = 0
			}

		// 每小时清除历史数据
		case <-cleanTimer.C:
			_, err := raspHbCol.DeleteMany(context.Background(), bson.M{"update_time": bson.M{"$lte": time.Now().Unix() - 3600}})
			if err != nil {
				ylog.Errorf("Delete error", err.Error())
			}
		}
	}
}

func (w *leaderRaspWriter) Add(v interface{}) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("leaderRaspWriter", "main channel is full len %d", len(w.queue))
	}
}
