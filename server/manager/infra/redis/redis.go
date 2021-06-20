package redis

import (
	"context"
	"github.com/go-redis/redis/v8"
)

func NewRedisClient(addrs []string, passwd string) (redis.UniversalClient, error) {
	client := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    addrs,
		Password: passwd,
	})
	defer client.Close()

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}
	return client, nil
}
