package kafka

import (
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	jsoniter "github.com/json-iterator/go"
	"sync"
	"time"

	"github.com/Shopify/sarama"
)

var bytesPool *sync.Pool
var json = jsoniter.Config{
	EscapeHTML:             false, //No html escaping
	SortMapKeys:            false,
	ValidateJsonRawMessage: true,
}.Froze()

func init() {
	bytesPool = &sync.Pool{
		New: func() interface{} {
			return nil
		},
	}
}

// BSerialize, use bytesPool
func BSerialize(v interface{}) ([]byte, error) {
	stream := json.BorrowStream(nil)
	defer json.ReturnStream(stream)
	stream.WriteVal(v)
	if stream.Error != nil {
		return nil, stream.Error
	}
	result := stream.Buffer()
	rLen := len(result)

	var copied []byte
	tmp := bytesPool.Get()
	if tmp != nil {
		copied = tmp.([]byte)
		if cap(copied) < rLen {
			copied = make([]byte, rLen)
		}
	} else {
		copied = make([]byte, rLen)
	}

	copy(copied[:rLen], result)
	return copied[:rLen], nil
}

// Producer represents the kafka async producer
type Producer struct {
	Producer sarama.AsyncProducer
	Topic    string
}

//NewProducer creates kafka async producer
func NewProducerWithLog(addrs []string, topic string, clientID string, logPath string) (*Producer, error) {
	logger := ylog.NewYLog(
		ylog.WithLogFile(logPath),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(ylog.InfoLevel),
	)
	logger.SetMsg("Sarama")
	sarama.Logger = logger
	return NewProducer(addrs, topic, clientID)
}

//NewProducer creates kafka async producer
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
				v, err := succ.Value.Encode()
				if err != nil {
					bytesPool.Put(v)
				}
				ylog.Debugf("KAFKA", "send msg succ, topic:%s, patition:%d, offset:%d", succ.Topic, succ.Partition, succ.Offset)

			case err := <-producer.Errors():
				ylog.Errorf("KAFKA", "send msg error:%v", err)
			}
		}
	}()

	return &Producer{Producer: producer, Topic: topic}, nil
}

//send message with key
func (p *Producer) SendWithKey(key string, msg interface{}) {
	b, err := BSerialize(msg)
	if err != nil {
		ylog.Errorf("KAFKA", "SendWithKey Error %v", err)
		return
	}
	p.Producer.Input() <- &sarama.ProducerMessage{Topic: p.Topic, Value: sarama.ByteEncoder(b), Key: sarama.StringEncoder(key)}
}
