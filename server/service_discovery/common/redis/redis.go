package redis

import (
	"context"
	"github.com/go-redis/redis/v8"
)

func NewRedisClient(addrs []string, masterName, passwd string) (redis.UniversalClient, error) {
	client := redis.NewUniversalClient(&redis.UniversalOptions{
		MasterName: masterName,
		Addrs:      addrs,
		Password:   passwd,
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}
	return client, nil
}
