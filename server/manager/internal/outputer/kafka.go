package outputer

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Shopify/sarama"
	"github.com/bytedance/Elkeid/server/manager/infra/kafka"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

type KafkaWorker struct {
	producer  sarama.AsyncProducer
	stop      chan bool
	level_map map[string]int
	msg_type  string
	topic     string
	Queue     chan *DataModel
}

func (b *KafkaWorker) Init(conf *OutputerConfig) error {
	if conf == nil || conf.MsgConfig.Kafka == nil {
		return errors.New("empty config for output kafka worker")
	}
	b.stop = make(chan bool)
	var oConf = make(map[string]interface{}, 0)
	if strings.TrimSpace(conf.MsgConfig.Kafka.KafkaOtherConf) != "" {
		err := json.Unmarshal([]byte(conf.MsgConfig.Kafka.KafkaOtherConf), &oConf)
		if err != nil {
			ylog.Errorf("KafkaWorker", "json.Unmarshal Error %s", err.Error())
			return err
		}
	}

	producer, err := kafka.NewProducer(conf.MsgConfig.Kafka.KafkaBootstrapServers, oConf, "elkeid_kafka_oupter", b.stop)
	if err != nil {
		ylog.Errorf("KafkaWorker", "Init Error %s", err.Error())
		return err
	}
	b.producer = producer
	b.topic = conf.MsgConfig.Kafka.KafkaTopic
	b.msg_type = conf.Type
	b.level_map = make(map[string]int)
	for _, one := range conf.LevelList {
		b.level_map[one] = 1
	}

	// init channel
	b.Queue = make(chan *DataModel, ConfigOutputerQueueMax)

	// init coroutine
	go b.WaitForInputMsg()

	return nil
}
func (b *KafkaWorker) WaitForInputMsg() {
	for {
		if d, ok := <-b.Queue; ok {
			if d != nil {
				bv, err := json.Marshal(d.Data)
				if err != nil {
					ylog.Errorf("BMQWorker", "SendMsg Marshal error %s", err.Error())
					return
				}

				ylog.Debugf("SendMsg", "SendMsg %#v", d)
				b.producer.Input() <- &sarama.ProducerMessage{Topic: b.topic, Value: sarama.ByteEncoder(bv)}
			}
		} else {
			ylog.Infof("stop KafkaWorker for", "topic %s", b.topic)
			return
		}
	}
}

func (b *KafkaWorker) HitModel(model DataHitModelInfo) bool {
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

func (b *KafkaWorker) SendMsg(dm *DataModel) {
	if dm == nil {
		return
	}

	select {
	case b.Queue <- dm:
		return
	default:
		ylog.Errorf("channel blocked in KafkaWorker for", "topic %s", b.topic)
	}
}

func (b *KafkaWorker) Close() {
	// close the channel
	close(b.Queue)
	close(b.stop)
}
