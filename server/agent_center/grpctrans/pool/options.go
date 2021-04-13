package pool

import "time"

const (
	defaultPoolLength        = 1024
	defaultConfigChanLength  = 1024
	defaultTaskChanLength    = 1024
	defaultCommSendTimeOut   = 2 * time.Second
	defaultCommResultTimeOut = 2 * time.Second
	defaultTaskTimeWeight    = 10 * time.Second
	defaultTaskCountWeight   = 100
)

type Config struct {
	PoolLength        int
	ConfigChanLen     int
	TaskChanLen       int
	CommSendTimeOut   time.Duration
	CommResultTimeOut time.Duration
	TaskTimeWeight    time.Duration
	TaskCountWeight   int
}

func NewConfig() *Config {
	c := &Config{
		PoolLength:        defaultPoolLength,
		ConfigChanLen:     defaultConfigChanLength,
		TaskChanLen:       defaultTaskChanLength,
		CommSendTimeOut:   defaultCommSendTimeOut,
		CommResultTimeOut: defaultCommResultTimeOut,
		TaskTimeWeight:    defaultTaskTimeWeight,
		TaskCountWeight:   defaultTaskCountWeight,
	}
	return c
}
