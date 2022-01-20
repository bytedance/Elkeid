package pool

import "time"

const (
	defaultPoolLength        = 1024
	defaultChanLength        = 1024
	defaultCommSendTimeOut   = 2 * time.Second
	defaultCommResultTimeOut = 2 * time.Second
	defaultTaskTimeWeight    = 10 * time.Second
	defaultTaskCountWeight   = 100
	defaultInterval          = 240 * time.Second
)

type Config struct {
	PoolLength        int
	ChanLen           int
	CommSendTimeOut   time.Duration
	CommResultTimeOut time.Duration
	TaskTimeWeight    time.Duration
	TaskCountWeight   int
	Interval          time.Duration
}

func NewConfig() *Config {
	c := &Config{
		PoolLength:        defaultPoolLength,
		ChanLen:           defaultChanLength,
		CommSendTimeOut:   defaultCommSendTimeOut,
		CommResultTimeOut: defaultCommResultTimeOut,
		TaskTimeWeight:    defaultTaskTimeWeight,
		TaskCountWeight:   defaultTaskCountWeight,
		Interval:          defaultInterval,
	}
	return c
}
