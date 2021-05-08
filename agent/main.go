package main

import (
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/bytedance/Elkeid/agent/global"
	"github.com/bytedance/Elkeid/agent/log"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/report"
	"github.com/bytedance/Elkeid/agent/transport"

	_ "net/http/pprof"

	"github.com/nightlyone/lockfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	if runtime.NumCPU() >= 8 {
		runtime.GOMAXPROCS(8)
	}
}
func main() {
	defer func() {
		if err := recover(); err != nil {
			zap.S().Errorf("Main func panic:%v", err)
			time.Sleep(time.Second)
			panic(err)
		}
	}()
	config := zap.NewProductionEncoderConfig()
	config.CallerKey = "source"
	config.TimeKey = "timestamp"
	config.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	grpcEncoder := zapcore.NewJSONEncoder(config)
	grpcWriter := zapcore.AddSync(&log.LoggerWriter{})
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "log/elkeid-agent.log",
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(zapcore.NewCore(grpcEncoder, grpcWriter, zap.ErrorLevel), zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel))
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	undo := zap.ReplaceGlobals(logger)
	defer undo()
	lock, err := lockfile.New("/var/run/elkeid-agent.pid")
	if err != nil {
		zap.S().Panicf("%v", err)
	}
	if err = lock.TryLock(); err != nil {
		zap.S().Panicf("%v", err)
	}
	defer lock.Unlock()
	zap.S().Infof("Elkeid Agent:v%s", global.Version)
	zap.S().Infof("AgentID:%s", global.AgentID)
	zap.S().Infof("PrivateIPv4:%v", global.PrivateIPv4)
	zap.S().Infof("PublicIPv4:%v", global.PublicIPv4)
	zap.S().Infof("PrivateIPv6:%v", global.PrivateIPv6)
	zap.S().Infof("PublicIPv6:%v", global.PublicIPv6)
	zap.S().Infof("Hostname:%v", global.Hostname)
	go plugin.Run()
	go transport.Run()
	go report.Run()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigs
	zap.S().Infof("Receive signal %v", sig.String())
	s, err := plugin.GetServer()
	if err == nil {
		s.Close()
	}
}
