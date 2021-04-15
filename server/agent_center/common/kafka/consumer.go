package kafka

import (
	"github.com/Shopify/sarama"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"sync"
)

// Consumer 消费者
type Consumer struct {
	Consumer sarama.Consumer
	Topic    string
}

//NewProducer creates kafka async producer
func NewConsumerWithLog(addrs []string, topic string, logPath string) (*Consumer, error) {
	logger := ylog.NewYLog(
		ylog.WithLogFile(logPath),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(ylog.InfoLevel),
	)
	logger.SetMsg("Sarama")
	sarama.Logger = logger
	return NewConsumer(addrs, topic)
}

func NewConsumer(addrs []string, topic string) (*Consumer, error) {
	config := sarama.NewConfig()
	config.Consumer.Offsets.Initial = sarama.OffsetNewest

	//create async producer
	client, err := sarama.NewClient(addrs, config)
	if err != nil {
		ylog.Errorf("KAFKA", "NewClient error:%s", err.Error())
		return nil, err
	}

	consumer, err := sarama.NewConsumerFromClient(client)
	if err != nil {
		ylog.Errorf("KAFKA", "NewConsumerFromClient error:%s", err.Error())
		return nil, err
	}

	return &Consumer{Consumer: consumer, Topic: topic}, nil
}

func (c *Consumer) StartConsume() {
	partitionList, err := c.Consumer.Partitions(c.Topic)
	if err != nil {
		ylog.Errorf("KAFKA", "Partitions error:%s", err.Error())
		return
	}

	thr := sync.WaitGroup{}
	for partition := range partitionList {
		thr.Add(1)
		go consume(&thr, c.Topic, int32(partition), c.Consumer)
	}
	thr.Wait()
}

func consume(thr *sync.WaitGroup, topic string, partition int32, consumer sarama.Consumer) {
	defer thr.Done()
	pc, err := consumer.ConsumePartition(topic, partition, sarama.OffsetNewest)
	if err != nil {
		ylog.Errorf("KAFKA", "ConsumePartition error:%s", err.Error())
		return
	}
	defer pc.AsyncClose()

	for {
		select {
		case msg := <-pc.Messages():
			ylog.Infof("KAFKA", "Partition:%d, Offset:%d, Key:%s, Value:%s", msg.Partition, msg.Offset, string(msg.Key), string(msg.Value))
		case err := <-pc.Errors():
			ylog.Errorf("KAFKA", "error %s", err.Error())
			if err.Err == sarama.ErrClosedClient {
				return
			}
		}
	}
}
