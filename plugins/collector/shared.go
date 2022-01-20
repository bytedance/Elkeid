package main

import (
	"math/rand"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/bytedance/plugins"
	"github.com/go-logr/zapr"
	"github.com/patrickmn/go-cache"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

var (
	Scheduler   = cron.New(cron.WithChain(cron.SkipIfStillRunning(zapr.NewLogger(zap.L()))))
	SchedulerMu = &sync.Mutex{}
	Client      = plugins.New()
	userCache   = cache.New(time.Hour*time.Duration(2), time.Minute*time.Duration(30))
)

func init() {
	rand.Seed(time.Now().UnixNano())
}
func GetUsername(uid int) (username string) {
	uidStr := strconv.Itoa(uid)
	if u, ok := userCache.Get(uidStr); ok {
		username = u.(string)
	} else {
		u, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			return
		}
		username = u.Username
		userCache.Add(uidStr, username, time.Minute*time.Duration(rand.Intn(60)+60))
	}
	return
}
