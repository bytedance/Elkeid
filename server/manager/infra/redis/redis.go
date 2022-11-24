package redis

import (
	"context"
	"github.com/go-redis/redis/v8"
)

func NewRedisClient(addrs []string, masterName, passwd string) (redis.UniversalClient, error) {
	if masterName != "" {
		if len(addrs) == 0 {
			addrs = []string{"127.0.0.1:26379"}
		}
		opts := &redis.FailoverOptions{
			SentinelAddrs: addrs,
			MasterName:    masterName,
			Password:      passwd,
		}
		client := redis.NewFailoverClient(opts)

		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return nil, err
		}

		return client, nil
	} else if len(addrs) > 1 {
		if len(addrs) == 0 {
			addrs = []string{"127.0.0.1:26379"}
		}
		opts := &redis.ClusterOptions{
			Addrs:    addrs,
			Password: passwd,
		}
		client := redis.NewClusterClient(opts)

		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return nil, err
		}

		return client, nil
	} else {
		addr := "127.0.0.1:6379"
		if len(addrs) > 0 {
			addr = addrs[0]
		}
		opts := &redis.Options{
			Addr:     addr,
			Password: passwd,
		}
		client := redis.NewClient(opts)

		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return nil, err
		}

		return client, nil
	}
}
