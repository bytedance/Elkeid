package redis

import (
	"context"
	"errors"
	"github.com/go-redis/redis/v8"
)

func NewRedisClient(addr string, addrs []string, passwd string) (redis.Cmdable, error) {
	//single
	if addr != "" {
		client := redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: passwd,
		})

		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return nil, err
		}
		return client, nil
	}

	//cluster
	if addrs != nil && len(addrs) != 0 {
		client := redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    addrs,
			Password: passwd,
		})

		_, err := client.Ping(context.Background()).Result()
		if err != nil {
			return nil, err
		}

		return client, nil
	}

	return nil, errors.New("all addresses are empty")
}
