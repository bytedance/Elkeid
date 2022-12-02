package kafka

import (
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"

	"github.com/Shopify/sarama"
)

// NewProducer creates kafka async producer
func NewProducer(addr string, otherConfig map[string]interface{}, clientID string, stop chan bool) (sarama.AsyncProducer, error) {
	addrs := strings.Split(addr, ",")
	config := sarama.NewConfig()
	config.ClientID = clientID
	config.Producer.Return.Successes = false
	config.Producer.MaxMessageBytes = 1024 * 1024 * 4 //4M
	config.Producer.Timeout = 6 * time.Second
	config.Producer.Flush.Bytes = 1024 * 1024 * 4
	config.Producer.Flush.MaxMessages = 1024 * 1024 * 4
	config.Producer.Flush.Frequency = 10 * time.Second

	if _, ok := otherConfig["sasl.mechanism"]; ok {
		if otherConfig["sasl.mechanism"] == "PLAIN" {
			config.Net.SASL.Mechanism = "PLAIN"
		}
		if otherConfig["sasl.mechanism"] == "OAUTHBEARER" {
			config.Net.SASL.Mechanism = "OAUTHBEARER"
		}
	}
	if _, ok := otherConfig["sasl.password"]; ok {
		config.Net.SASL.Password = otherConfig["sasl.password"].(string)
	}
	if _, ok := otherConfig["sasl.username"]; ok {
		config.Net.SASL.User = otherConfig["sasl.username"].(string)
	}
	if res, ok := otherConfig["security.protocol"]; ok {
		if res == "SASL_PLAINTEXT" {
			config.Net.SASL.Enable = true
		}
		if res == "SASL_SSL" {
			config.Net.SASL.Enable = true
		}
		if res == "PLAINTEXT" {
			config.Net.SASL.Enable = false
		}
	}

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
			case err := <-producer.Errors():
				ylog.Errorf("KAFKA", "send msg error:%s", err.Error())
			case <-stop:
				_ = producer.Close()
				return
			}
		}
	}()

	return producer, nil
}
