package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/Shopify/sarama"
	"github.com/bytedance/ByteDance-HIDS/agent/common"
	"github.com/bytedance/ByteDance-HIDS/agent/config"
	"github.com/bytedance/ByteDance-HIDS/agent/health"
	"github.com/bytedance/ByteDance-HIDS/agent/log"
	"github.com/bytedance/ByteDance-HIDS/agent/plugin"
	"github.com/bytedance/ByteDance-HIDS/agent/transport"
	"github.com/bytedance/ByteDance-HIDS/agent/transport/fileout"
	"github.com/bytedance/ByteDance-HIDS/agent/transport/kafka"
	"github.com/jessevdk/go-flags"

	"github.com/nightlyone/lockfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var opts struct {
	Version  bool   `short:"v" long:"version" description:"Print agent version"`
	Plugin   string `long:"plugin" description:"Plugin socket path" default:"plugin.sock"`
	Log      string `long:"log" description:"Log file path" default:"log/agent_smith.log"`
	Config   string `long:"config" description:"Config file path(.yaml)" default:"config.yaml"`
	Data     string `long:"data" choice:"file" choice:"stdout" choice:"kafka" description:"Set data output" default:"stdout"`
	FilePath string `long:"file_path" description:"If data option is file ,this option is used to set the file path" default:"data.log"`
	Addr     string `long:"addr" description:"If data option is kafka ,this option is used to set kafka addr"`
	Topic    string `long:"topic" description:"If data option is kafka ,this option is used to set kafka topic name"`
}

func init() {
	if _, err := flags.ParseArgs(&opts, os.Args); err != nil {
		switch flagsErr := err.(type) {
		case *flags.Error:
			if flagsErr.Type == flags.ErrHelp {
				os.Exit(0)
			}
		}
		os.Exit(1)
	}
	if opts.Version {
		fmt.Println("Agent version :", common.Version)
		os.Exit(0)
	}
	if runtime.NumCPU() >= 8 {
		runtime.GOMAXPROCS(8)
	}
}
func main() {
	plugin.SocketPath = opts.Plugin
	config.ConfigPath = opts.Config
	switch opts.Data {
	case "stdout":
	case "file":
		fo, err := fileout.NewFileOut(opts.FilePath)
		defer fo.Close()
		if err != nil {
			zap.S().Panic(err)
		} else {
			transport.SetTransport(fo)
		}
	case "kafka":
		cfg := sarama.NewConfig()
		cfg.Producer.Return.Successes = true
		client, err := sarama.NewClient([]string{opts.Addr}, cfg)
		if err != nil {
			zap.S().Panic(err)
		}
		k, err := kafka.NewKafka(client, opts.Topic)
		if err != nil {
			zap.S().Panic(err)
		}
		transport.SetTransport(k)
	}
	lock, err := lockfile.New("/var/run/agent_smith.pid")
	if err != nil {
		zap.S().Panicf("%v", err)
	}
	if err = lock.TryLock(); err != nil {
		zap.S().Panicf("%v", err)
	}
	defer lock.Unlock()

	logConfig := zap.NewProductionEncoderConfig()
	logConfig.CallerKey = "source"
	logConfig.TimeKey = "timestamp"
	logConfig.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	remoteEncoder := zapcore.NewJSONEncoder(logConfig)
	remoteWriter := zapcore.AddSync(&log.LoggerWriter{})
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   opts.Log,
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(zapcore.NewCore(remoteEncoder, remoteWriter, zap.ErrorLevel), zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel))
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	undo := zap.ReplaceGlobals(logger)
	defer undo()

	zap.S().Infof("Agent Smith Version:v%s", common.Version)
	zap.S().Infof("Agent ID:%s", common.AgentID)
	zap.S().Infof("Private IPv4:%v", common.PrivateIPv4)
	zap.S().Infof("Public IPv4:%v", common.PublicIPv4)
	zap.S().Infof("Private IPv6:%v", common.PrivateIPv6)
	zap.S().Infof("Public IPv6:%v", common.PublicIPv6)
	zap.S().Infof("Hostname:%v", common.Hostname)

	go health.Start()
	go config.Watcher()
	go plugin.Run()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	select {
	case sig := <-sigs:
		zap.S().Infof("Receive signal %v", sig.String())
	}
}
