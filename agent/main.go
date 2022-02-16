package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/bytedance/Elkeid/agent/agent"
	"github.com/bytedance/Elkeid/agent/heartbeat"
	"github.com/bytedance/Elkeid/agent/host"
	"github.com/bytedance/Elkeid/agent/log"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/transport"
	"github.com/nightlyone/lockfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// 手动设置，防止采用默认值导致GC时间大幅度上升
	runtime.GOMAXPROCS(8)
}

func main() {
	// 初始化logger
	grpcConfig := zap.NewProductionEncoderConfig()
	grpcConfig.CallerKey = "source"
	grpcConfig.TimeKey = "timestamp"
	grpcConfig.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	grpcEncoder := zapcore.NewJSONEncoder(grpcConfig)
	grpcWriter := &log.GrpcWriter{}

	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "log/" + agent.Product + ".log",
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	var core zapcore.Core
	if os.Getenv("RUNTIME_MODE") == "DEBUG" {
		core = zapcore.NewTee(zapcore.NewCore(grpcEncoder, grpcWriter, zap.ErrorLevel), zapcore.NewCore(fileEncoder, fileWriter, zap.DebugLevel))
	} else {
		core = zapcore.NewTee(
			zapcore.NewSamplerWithOptions(
				zapcore.NewCore(grpcEncoder, grpcWriter, zap.ErrorLevel), time.Second, 4, 1),
			zapcore.NewSamplerWithOptions(
				zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel), time.Second, 4, 1),
		)
	}
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	zap.ReplaceGlobals(logger)
	if os.Getenv("service_type") == "sysvinit" {
		l, _ := lockfile.New("/var/run/elkeid-agent.pid")
		if err := l.TryLock(); err != nil {
			zap.S().Error(err)
			return
		}
	}
	zap.S().Info("++++++++++++++++++++++++++++++startup++++++++++++++++++++++++++++++")
	zap.S().Info("product:", agent.Product)
	zap.S().Info("version:", agent.Version)
	zap.S().Info("id:", agent.ID)
	zap.S().Info("hostname:", host.Name.Load())
	zap.S().Infof("intranet_ipv4:%v", host.PrivateIPv4.Load())
	zap.S().Infof("intranet_ipv6:%v", host.PrivateIPv6.Load())
	zap.S().Infof("extranet_ipv4:%v", host.PublicIPv4.Load())
	zap.S().Infof("extranet_ipv6:%v", host.PublicIPv6.Load())
	zap.S().Info("platform:", host.Platform)
	zap.S().Info("platform_family:", host.PlatformFamily)
	zap.S().Info("platform_version:", host.PlatformVersion)
	zap.S().Info("kernel_version:", host.KernelVersion)
	zap.S().Info("arch:", host.Arch)
	// 同步task，但是注意：不要把wg传递到子gorountine中，每个task应该要保证退出前等待并关闭所有子gorountine
	wg := &sync.WaitGroup{}
	logger.Info("++++++++++++++++++++++++++++++running++++++++++++++++++++++++++++++")
	wg.Add(3)
	go heartbeat.Startup(agent.Context, wg)
	go plugin.Startup(agent.Context, wg)
	go func() {
		transport.Startup(agent.Context, wg)
		agent.Cancel()
	}()
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		sig := <-sigs
		zap.S().Error("receive signal:", sig.String())
		zap.S().Info("wait for 5 secs to exit")
		<-time.After(time.Second * 5)
		agent.Cancel()
	}()
	if os.Getenv("RUNTIME_MODE") == "DEBUG" {
		go http.ListenAndServe("0.0.0.0:6060", nil)
	}
	wg.Wait()
	logger.Info("++++++++++++++++++++++++++++++exit++++++++++++++++++++++++++++++")
}
