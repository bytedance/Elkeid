package kafka

import (
	"encoding/json"

	"github.com/Shopify/sarama"
	"github.com/bytedance/AgentSmith-HIDS/agent/spec"
	"github.com/bytedance/AgentSmith-HIDS/agent/transport"
	"go.uber.org/zap"
)

type Kafka struct {
	c sarama.Client
	p sarama.SyncProducer
	t string
}

func NewKafka(c sarama.Client, topic string) (transport.Transport, error) {
	producer, err := sarama.NewSyncProducerFromClient(c)
	if err != nil {
		return nil, err
	}
	return &Kafka{c, producer, topic}, nil
}

func (k *Kafka) Send(d *spec.Data) error {
	content, err := json.Marshal(d)
	if err != nil {
		return err
	}
	partition, offset, err := k.p.SendMessage(&sarama.ProducerMessage{Topic: k.t, Value: sarama.ByteEncoder(content)})
	zap.S().Debug("Kafka send message:%v %v", partition, offset)
	return err
}

func (k *Kafka) Receive() (spec.Task, error) {
	select {}
}

func (k *Kafka) Close() {
	k.p.Close()
	k.c.Close()
}
