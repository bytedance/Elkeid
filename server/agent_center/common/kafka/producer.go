package kafka

import (
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/gogo/protobuf/proto"
	jsoniter "github.com/json-iterator/go"
	"sync"
	"time"

	"github.com/Shopify/sarama"
)

var (
	MQMsgPool = &sync.Pool{
		New: func() interface{} {
			return &pb.MQData{}
		},
	}

	mqProducerMessagePool = &sync.Pool{
		New: func() interface{} {
			return &sarama.ProducerMessage{}
		},
	}
)

var json = jsoniter.Config{
	EscapeHTML:             false, //不进行html转义
	SortMapKeys:            false,
	ValidateJsonRawMessage: true,
}.Froze()

// JsonSerialize
func JsonSerialize(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// PBSerialize
func PBSerialize(v proto.Message) ([]byte, error) {
	return proto.Marshal(v)
}

// Producer represents the kafka async producer
type Producer struct {
	Producer sarama.AsyncProducer
	Topic    string
}

// NewProducer creates kafka async producer
func NewProducerWithLog(addrs []string, topic, clientID, logPath, userName, passWord string, enableAuth bool) (*Producer, error) {
	logger := ylog.NewYLog(
		ylog.WithLogFile(logPath),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(ylog.InfoLevel),
	)
	logger.SetMsg("Sarama")
	sarama.Logger = logger

	config := sarama.NewConfig()
	config.ClientID = clientID
	config.Producer.Return.Successes = true
	config.Producer.MaxMessageBytes = 1024 * 1024 * 4 //4M
	config.Producer.Timeout = 6 * time.Second
	config.Producer.Flush.Bytes = 1024 * 1024 * 4
	config.Producer.Flush.MaxMessages = 1024 * 1024 * 4
	config.Producer.Flush.Frequency = 10 * time.Second
	config.Producer.Retry.Max = 1

	if enableAuth {
		config.Net.SASL.User = userName
		config.Net.SASL.Password = passWord
		config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		config.Net.SASL.Enable = enableAuth
	}

	return newProducerWithConfig(addrs, topic, config)
}

// NewProducer creates kafka async producer
func NewProducer(addrs []string, topic string, clientID string) (*Producer, error) {
	//initial config and log
	config := sarama.NewConfig()
	config.ClientID = clientID
	config.Producer.Return.Successes = true
	config.Producer.MaxMessageBytes = 1024 * 1024 * 4 //4M
	config.Producer.Timeout = 6 * time.Second
	config.Producer.Flush.Bytes = 1024 * 1024 * 4
	config.Producer.Flush.MaxMessages = 1024 * 1024 * 4
	config.Producer.Flush.Frequency = 10 * time.Second

	return newProducerWithConfig(addrs, topic, config)
}

// newProducerWithConfig creates kafka async producer
func newProducerWithConfig(addrs []string, topic string, config *sarama.Config) (*Producer, error) {
	//create async producer
	client, err := sarama.NewClient(addrs, config)
	if err != nil {
		ylog.Errorf("KAFKA", "NewClient error:%s", err.Error())
		return nil, err
	}

	producer, err := sarama.NewAsyncProducerFromClient(client)
	if err != nil {
		ylog.Errorf("KAFKA", "NewAsyncProducerFromClient error:%s", err.Error())
		return nil, err
	}

	go func() {
		for {
			select {
			case succ := <-producer.Successes():
				//Put back to sync.pool
				mqProducerMessagePool.Put(succ)
				ylog.Debugf("KAFKA", "send msg succ, topic:%s, patition:%d, offset:%d", succ.Topic, succ.Partition, succ.Offset)

			case err := <-producer.Errors():
				ylog.Errorf("KAFKA", "send msg error:%v", err)
			}
		}
	}()

	return &Producer{Producer: producer, Topic: topic}, nil
}

// Send 发送
func (p *Producer) SendPBWithKey(key string, msg proto.Message) {
	defer func() {
		MQMsgPool.Put(msg)
	}()
	b, err := PBSerialize(msg)
	if err != nil {
		ylog.Errorf("KAFKA", "SendPBWithKey Error %s", err.Error())
		return
	}

	proMsg := mqProducerMessagePool.Get().(*sarama.ProducerMessage)
	proMsg.Topic = p.Topic
	proMsg.Value = sarama.ByteEncoder(b)
	proMsg.Key = sarama.StringEncoder(key)
	proMsg.Metadata = nil
	p.Producer.Input() <- proMsg
}

// Send 发送
func (p *Producer) SendJsonWithKey(key string, msg interface{}) {
	b, err := JsonSerialize(msg)
	if err != nil {
		ylog.Errorf("SendJsonWithKey", "Error %v", err)
		return
	}

	proMsg := mqProducerMessagePool.Get().(*sarama.ProducerMessage)
	proMsg.Topic = p.Topic
	proMsg.Value = sarama.ByteEncoder(b)
	proMsg.Key = sarama.StringEncoder(key)
	proMsg.Metadata = nil
	p.Producer.Input() <- proMsg
}
