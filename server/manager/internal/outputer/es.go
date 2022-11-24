package outputer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/es"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/olivere/elastic/v7"
)

type EsWorker struct {
	client             *elastic.Client
	producer           *elastic.BulkProcessor
	esIndex            string
	esIndexRefreshType string
	esIndexReal        string
	level_map          map[string]int
	msg_type           string
	ctx                context.Context
	cancelButten       context.CancelFunc
	Queue              chan *DataModel
}

func (b *EsWorker) Init(conf *OutputerConfig) error {
	if conf == nil || conf.MsgConfig.ES == nil {
		return errors.New("empty config for output es worker")
	}

	// hosts := strings.Split(conf.MsgConfig.ES.ESHost, ",")
	esConfig := es.EsConfig{
		EsAuthUser:   conf.MsgConfig.ES.ESAuthUser,
		EsAuthPasswd: conf.MsgConfig.ES.ESAuthPasswd,
		Host:         conf.MsgConfig.ES.ESHost,
	}
	client, err := es.NewEsClient(&esConfig)
	if err != nil {
		ylog.Errorf("EsWorker", "Init Error %s", err.Error())
		return err
	}

	p, err := client.BulkProcessor().
		Name("elkeid_es_oupter").
		BulkActions(1000). // commit if # requests >= 1000
		BulkSize(2 << 20). // commit if size of requests >= 2 MB
		FlushInterval(30 * time.Second).
		After(func(executionId int64, requests []elastic.BulkableRequest, response *elastic.BulkResponse, err error) {
			if err != nil {
				ylog.Errorf("EsWorker", "BulkProcessor error %s", err.Error())
			}
			if response != nil && response.Errors && len(response.Failed()) > 0 {
				ylog.Errorf("EsWorker", "BulkProcessor response error %#v detail %s",
					response.Failed()[0], response.Failed()[0].Error.Reason)
			}
		}).
		Do(context.Background())

	b.client = client
	b.producer = p
	b.msg_type = conf.Type
	b.level_map = make(map[string]int)
	for _, one := range conf.LevelList {
		b.level_map[one] = 1
	}
	b.esIndexRefreshType = conf.MsgConfig.ES.ESIndexRefreshType
	b.esIndex = conf.MsgConfig.ES.ESIndex
	b.ctx, b.cancelButten = context.WithCancel(context.Background())
	// run index refresh
	b.ESRefreshIndex()

	// init channel
	b.Queue = make(chan *DataModel, ConfigOutputerQueueMax)

	// init coroutine
	go b.WaitForInputMsg()

	return nil
}

func (b *EsWorker) WaitForInputMsg() {
	for {
		if d, ok := <-b.Queue; ok {
			if d != nil {
				// copy the data to remove the _id field
				var bv = make([]byte, 0)
				dataMap, ok := d.Data.(map[string]interface{})
				if !ok {
					tmpBv, err := json.Marshal(d.Data)
					if err != nil {
						ylog.Errorf("EsWorker", "SendMsg Marshal error %s", err.Error())
						return
					}
					bv = append(bv, tmpBv...)
				} else {
					newDataMap := make(map[string]interface{})
					for k, v := range dataMap {
						if k == "_id" {
							newDataMap["elkeid_db_id"] = v
						} else {
							newDataMap[k] = v
						}
					}

					tmpBv, err := json.Marshal(newDataMap)
					if err != nil {
						ylog.Errorf("EsWorker", "SendMsg Marshal error %s", err.Error())
						return
					}
					bv = append(bv, tmpBv...)
				}

				r := elastic.NewBulkIndexRequest().Index(b.esIndexReal).Doc(string(bv))
				b.producer.Add(r)
			}
		} else {
			ylog.Infof("stop EsWorker for", "index %s", b.esIndex)
			return
		}
	}
}

func (b *EsWorker) HitModel(model DataHitModelInfo) bool {
	if model.Model == b.msg_type {
		if len(b.level_map) > 0 {
			_, ok := b.level_map[model.Level]
			if ok {
				return true
			}
		} else {
			return true
		}
	}

	return false
}

func (b *EsWorker) SendMsg(dm *DataModel) {
	if dm == nil {
		return
	}

	select {
	case b.Queue <- dm:
		return
	default:
		ylog.Errorf("channel blocked in EsWorker for", "index %s", b.esIndex)
	}
}

func (b *EsWorker) Close() {
	b.cancelButten()
	b.client.Stop()
	// close the channel
	close(b.Queue)
}

// Hour / Day
func (b *EsWorker) ESRefreshIndex() {
	if b.esIndexRefreshType == "day" {
		b.esIndexReal = b.esIndex + "_" + getDay()
		go func() {
			for {
				select {
				case <-b.ctx.Done():
					return
				default:
					time.Sleep(5 * time.Second)
					b.esIndexReal = b.esIndex + "_" + getDay()
				}
			}
		}()
	} else if b.esIndexRefreshType == "hour" {
		b.esIndexReal = b.esIndex + "_" + getHour()
		go func() {
			for {
				select {
				case <-b.ctx.Done():
					return
				default:
					time.Sleep(5 * time.Second)
					b.esIndexReal = b.esIndex + "_" + getHour()
				}
			}
		}()
	} else {
		b.esIndexReal = b.esIndex
	}
}

func getHour() string {
	t := time.Now()
	return fmt.Sprintf("%d%d%d%d", t.Year(), t.Month(), t.Day(), t.Hour())
}

func getDay() string {
	t := time.Now()
	return fmt.Sprintf("%d%d%d", t.Year(), t.Month(), t.Day())
}
