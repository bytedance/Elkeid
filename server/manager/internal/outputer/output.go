package outputer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
)

// db config
type Config struct {
	ID    string   `json:"id" bson:"id"`
	Type  string   `json:"type" bson:"type"`
	Model []string `json:"model" bson:"model"`

	Address []string `json:"address" bson:"address"`
	Topic   string   `json:"topic" bson:"topic"`
	SASL    struct {
		Enable   bool   `json:"enable" bson:"enable"`
		UserName string `json:"username" bson:"username"`
		PassWord string `json:"password" bson:"password"`
	} `json:"sasl" bson:"sasl"`

	InsertTime int64 `json:"insert_time" bson:"insert_time"`
	UpdateTime int64 `json:"update_time" bson:"update_time"`
}

// data
type DataHitModelInfo struct {
	Model    string `json:"model" bson:"model"`
	SubModel string `json:"sub_model" bson:"sub_model"`
	Type     string `json:"type" bson:"type"`
	Level    string `json:"level" bson:"level"`
}

type DataModel struct {
	HitModel DataHitModelInfo `json:"hit_model" bson:"hit_model"`
	Filter   interface{}      `json:"filter" bson:"filter"`
	Data     interface{}      `json:"data" bson:"data"`
}

const (
	DataModelHidsAlarm           string = "hids alarm"
	DataModelRaspAlarm           string = "rasp alarm"
	DataModelKubeAlarm           string = "kube alarm"
	DataModelVirusAlarm          string = "virus alarm"
	DataModelAuthorizationExpire string = "authorization expire"

	DataSubModelHidsAlarm  string = "hids"
	DataSubModelRaspAlarm  string = "rasp"
	DataSubModelKubeAlarm  string = "kube"
	DataSubModelVirusAlarm string = "virus"

	DataTypeInsert string = "insert"

	ConfigTypeKafka    string = "kafka"
	ConfigTypeFeishu   string = "feishu"
	ConfigTypeDingding string = "dingding"
	ConfigTypeEmail    string = "email"
	ConfigTypeSyslog   string = "syslog"
	ConfigTypeEs       string = "elasticsearch"
	ConfigTypeEWechat  string = "enterprise wechat"
	ConfigTypeCustom   string = "custom"
)

const (
	ConfigOutputerOpen     int = 1
	ConfigOutputerQueueMax int = 100
)

func BuildDataModel(model, subModel, dType, alarmLevel string, filter, data interface{}) *DataModel {
	return &DataModel{
		HitModel: DataHitModelInfo{
			Model:    model,
			SubModel: subModel,
			Type:     dType,
			Level:    alarmLevel,
		},
		Filter: filter,
		Data:   data,
	}
}

type Worker struct {
	Conf  *OutputerConfig
	Queue chan *DataModel
}

type Handler struct {
	workers   map[string]OutWorker //id --> worker
	configMap map[string]int64     //id-->update_time
	lock      sync.Mutex
}

type OutWorker interface {
	Init(*OutputerConfig) error
	HitModel(DataHitModelInfo) bool //是否开启model
	SendMsg(*DataModel)
	Close()
}

// 使用update_time来识别是否需要更新
func (o *Handler) Init() error {
	o.workers = make(map[string]OutWorker, 0)
	o.configMap = make(map[string]int64, 0)

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
	cur, err := col.Find(context.Background(), bson.M{})
	if err != nil {
		ylog.Errorf("Handler", "Init error %s", err.Error())
		return err
	}

	for cur.Next(context.Background()) {
		conf := &OutputerConfig{}
		err := cur.Decode(conf)
		if err != nil {
			ylog.Errorf("Handler init", "Decode error %s", err.Error())
			continue
		}

		if conf.Status == ConfigOutputerOpen {
			err = o.UpdateConfig(conf)
			if err != nil {
				ylog.Errorf("outputer UpdateConfig for init error", "%s", err.Error())
				o.configMap[conf.ID] = -1
			} else {
				o.configMap[conf.ID] = conf.UpdateTime
			}
		} else {
			ylog.Infof("outputer config", "ID %s not open", conf.ID)
		}
	}

	//动态更新
	go func() {
		for {
			time.Sleep(time.Minute)

			col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.NoticeConfigCollectionV1)
			cur, err = col.Find(context.Background(), bson.M{})
			if err != nil {
				ylog.Errorf("Handler", "InitCheck error %s", err.Error())
				continue
			}

			toDelMap := make(map[string]int64, len(o.configMap))
			for k, v := range o.configMap {
				toDelMap[k] = v
			}

			//add or update
			for cur.Next(context.Background()) {
				conf := &OutputerConfig{}
				err := cur.Decode(conf)
				if err != nil {
					ylog.Errorf("Handler", "InitCheck error %s", err.Error())
					continue
				}

				if conf.Status == ConfigOutputerOpen {
					// remove from delete array
					delete(toDelMap, conf.ID)

					//是否动态改变
					if up, ok := o.configMap[conf.ID]; ok && up == conf.UpdateTime {
						continue
					} else {
						//stop old one
						if ok {
							ylog.Infof("Handler", "InitCheck close worker %s %#v.", conf.ID, conf)

							o.lock.Lock()
							l := o.workers[conf.ID]
							o.lock.Unlock()
							if l != nil {
								l.Close()
							}
						}

						err = o.UpdateConfig(conf)
						if err != nil {
							ylog.Errorf("Handler", "UpdateConfig for init error %s", err.Error())
							o.configMap[conf.ID] = -1
						} else {
							o.configMap[conf.ID] = conf.UpdateTime
						}
					}
				}
			}

			//del
			for k := range toDelMap {
				ylog.Infof("Handler", "InitCheck del worker %s.", k)

				o.lock.Lock()
				l := o.workers[k]
				delete(o.workers, k)
				o.lock.Unlock()

				if l != nil {
					l.Close()
				}
				delete(o.configMap, k)
			}
		}
	}()
	return nil
}

func (o *Handler) UpdateConfig(conf *OutputerConfig) error {
	if conf.Status != ConfigOutputerOpen {
		// not open
		errMsg := fmt.Sprintf("outputer config, ID %s is not open", conf.ID)
		return errors.New(errMsg)
	}

	switch conf.MsgType {
	case ConfigTypeKafka:
		worker := &KafkaWorker{}
		err := worker.Init(conf)
		if err != nil {
			ylog.Errorf("Handler", "Init error %s", err.Error())
			return err
		}
		ylog.Infof("Handler", "Init start worker %s %#v.", conf.ID, conf)
		o.lock.Lock()
		o.workers[conf.ID] = worker
		o.lock.Unlock()
	case ConfigTypeEs:
		worker := &EsWorker{}
		err := worker.Init(conf)
		if err != nil {
			ylog.Errorf("Handler", "Init error %s", err.Error())
			return err
		}
		ylog.Infof("Handler", "Init start worker %s %#v.", conf.ID, conf)
		o.lock.Lock()
		o.workers[conf.ID] = worker
		o.lock.Unlock()
	case ConfigTypeFeishu, ConfigTypeDingding, ConfigTypeEWechat, ConfigTypeEmail, ConfigTypeCustom:
		worker := &HubPluginWorker{}
		err := worker.Init(conf)
		if err != nil {
			ylog.Errorf("hubPluginWorker", "init error %s", err.Error())
			return err
		}
		ylog.Infof("hubPluginWorker", "Init start worker %s %#v.", conf.ID, conf)
		o.lock.Lock()
		o.workers[conf.ID] = worker
		o.lock.Unlock()
	case ConfigTypeSyslog:
		worker := &SyslogWorker{}
		err := worker.Init(conf)
		if err != nil {
			ylog.Errorf("syslogWorker", "init error %s", err.Error())
			return err
		}
		ylog.Infof("syslogWorker", "Init start worker %s %#v.", conf.ID, conf)
		o.lock.Lock()
		o.workers[conf.ID] = worker
		o.lock.Unlock()
	default:
		ylog.Errorf("unkown output type", "%s", conf.Type)
		return errors.New("unkown output type")
	}
	return nil
}

func (o *Handler) IsEnable() bool {
	if len(o.workers) == 0 {
		return false
	}
	return true
}

func (o *Handler) Add(dm *DataModel) {
	ylog.Debugf("new notice message add", "wokers num %d", len(o.workers))
	if len(o.workers) == 0 {
		return
	}

	o.lock.Lock()
	for k, v := range o.workers {
		ylog.Debugf("worker hit check", "wokers id %s", k)
		if v.HitModel(dm.HitModel) {
			ylog.Debugf("worker send message", "wokers id %s", k)
			v.SendMsg(dm)
		}
	}
	o.lock.Unlock()
}

var OuterHandler *Handler

func InitOutput() {
	go func() {
		OuterHandler = &Handler{}
		err := OuterHandler.Init()
		if err != nil {
			ylog.Errorf("OuterHandler", "Init Failed %s", err.Error())
		}
	}()
}

//dm := outputer.NewDataModel(outputer.DataModelTrace, outputer.DataSubModelTraceResult, outputer.DataTypeUpdate, bson.M{"trace_id": argv.TraceID}, res)
//outputer.OuterHandler.Add(dm)
