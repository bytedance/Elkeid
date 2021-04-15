package redis

import (
	"context"
	"github.com/go-redis/redis/v8"
)

func NewRedisClient(addrs []string, passwd string) (*redis.ClusterClient, error) {
	//client := redis.NewClient(&redis.Options{
	//	Addr:     addrs[0],
	//	Password: passwd,
	//})
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
