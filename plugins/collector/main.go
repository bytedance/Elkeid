package main

import (
	"math/rand"
	"runtime"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	plugins "github.com/bytedance/plugins"
	"github.com/bytedance/plugins/log"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	runtime.GOMAXPROCS(8)
	rand.Seed(time.Now().UnixNano())
}

func main() {
	c := plugins.New()
	l := log.New(
		log.Config{
			MaxSize:     1,
			Path:        "collector.log",
			FileLevel:   zapcore.InfoLevel,
			RemoteLevel: zapcore.ErrorLevel,
			MaxBackups:  10,
			Compress:    true,
			Client:      c,
		},
	)
	defer l.Sync()
	zap.ReplaceGlobals(l)
	e := engine.New(c, zapr.NewLogger(l))

	e.AddHandler(time.Hour, &ProcessHandler{})
	e.AddHandler(time.Hour, &PortHandler{})
	e.AddHandler(time.Hour*6, &UserHandler{})
	e.AddHandler(time.Hour*6, &CronHandler{})
	e.AddHandler(time.Hour*6, &ServiceHandler{})
	e.AddHandler(engine.BeforeDawn(), &SoftwareHandler{})
	e.AddHandler(time.Minute*5, &ContainerHandler{})
	e.AddHandler(engine.BeforeDawn(), &IntegrityHandler{})
	e.AddHandler(time.Hour*6, &NetInterfaceHandler{})
	e.AddHandler(time.Hour*6, &VolumeHandler{})
	e.AddHandler(time.Hour, &KmodHandler{})
	e.AddHandler(engine.BeforeDawn(), &AppHandler{})
	e.Run()
}
