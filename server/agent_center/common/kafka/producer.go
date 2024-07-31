package kafka

import (
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/gogo/protobuf/proto"
	jsoniter "github.com/json-iterator/go"
	"time"

	"github.com/Shopify/sarama"
)

// 定义全局的 JSON 序列化配置
var json = jsoniter.Config{
	EscapeHTML:             false,
	SortMapKeys:            false,
	ValidateJsonRawMessage: true,
}.Froze()

// JsonSerialize 序列化为 JSON
func JsonSerialize(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// PBSerialize 序列化为 Protobuf
func PBSerialize(v proto.Message) ([]byte, error) {
	return proto.Marshal(v)
}

// Producer represents the Kafka async producer
type Producer struct {
	Producer sarama.AsyncProducer
	Topic    string
}

// NewProducerWithLog 创建带日志的 Kafka 异步生产者
func NewProducerWithLog(addrs []string, topic, clientID, logPath, userName, passWord string, enableAuth bool) (*Producer, error) {
	config := createProducerConfig(clientID)
	if enableAuth {
		configureSASL(config, userName, passWord)
	}

	logger := ylog.NewYLog(
		ylog.WithLogFile(logPath),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(ylog.InfoLevel),
	)
	logger.SetMsg("Sarama")
	sarama.Logger = logger

	return newProducerWithConfig(addrs, topic, config)
}

// NewProducer 创建 Kafka 异步生产者
func NewProducer(addrs []string, topic, clientID string) (*Producer, error) {
	config := createProducerConfig(clientID)
	return newProducerWithConfig(addrs, topic, config)
}

// createProducerConfig 初始化生产者配置
func createProducerConfig(clientID string) *sarama.Config {
	config := sarama.NewConfig()
	config.ClientID = clientID
	config.Producer.Return.Successes = true
	config.Producer.MaxMessageBytes = 1024 * 1024 * 4 // 4M
	config.Producer.Timeout = 6 * time.Second
	config.Producer.Flush.Bytes = 1024 * 1024 * 4
	config.Producer.Flush.MaxMessages = 1024 * 1024 * 4
	config.Producer.Flush.Frequency = 10 * time.Second
	config.Producer.Compression = sarama.CompressionSnappy
	return config
}

// configureSASL 配置 SASL 认证
func configureSASL(config *sarama.Config, userName, passWord string) {
	config.Net.SASL.User = userName
	config.Net.SASL.Password = passWord
	config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
	config.Net.SASL.Enable = true
}

// newProducerWithConfig 使用配置创建 Kafka 异步生产者
func newProducerWithConfig(addrs []string, topic string, config *sarama.Config) (*Producer, error) {
	client, err := sarama.NewClient(addrs, config)
	if err != nil {
		ylog.Errorf("KAFKA", "NewClient error: %s", err)
		return nil, err
	}

	producer, err := sarama.NewAsyncProducerFromClient(client)
	if err != nil {
		ylog.Errorf("KAFKA", "NewAsyncProducerFromClient error: %s", err)
		return nil, err
	}

	go handleProducerEvents(producer)

	return &Producer{Producer: producer, Topic: topic}, nil
}

// handleProducerEvents 处理生产者事件
func handleProducerEvents(producer sarama.AsyncProducer) {
	for {
		select {
		case succ := <-producer.Successes():
			ylog.Debugf("KAFKA", "Message sent successfully, topic: %s, partition: %d, offset: %d", succ.Topic, succ.Partition, succ.Offset)
		case err := <-producer.Errors():
			ylog.Errorf("KAFKA", "Message send error: %v", err)
		}
	}
}

// SendPBWithKey 发送 Protobuf 消息
func (p *Producer) SendPBWithKey(key string, msg proto.Message) {
	b, err := PBSerialize(msg)
	if err != nil {
		ylog.Errorf("KAFKA", "SendPBWithKey Error: %s", err)
		return
	}
	p.sendMessage(key, b)
}

// SendJsonWithKey 发送 JSON 消息
func (p *Producer) SendJsonWithKey(key string, msg interface{}) {
	b, err := JsonSerialize(msg)
	if err != nil {
		ylog.Errorf("KAFKA", "SendJsonWithKey Error: %v", err)
		return
	}
	p.sendMessage(key, b)
}

// sendMessage 发送消息到 Kafka
func (p *Producer) sendMessage(key string, value []byte) {
	proMsg := &sarama.ProducerMessage{
		Topic: p.Topic,
		Value: sarama.ByteEncoder(value),
		Key:   sarama.StringEncoder(key),
	}
	p.Producer.Input() <- proMsg
}
