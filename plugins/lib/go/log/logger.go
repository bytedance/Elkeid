package log

import (
	"strconv"
	"time"

	plugins "github.com/bytedance/Elkeid/plugins"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Config struct {
	MaxSize     int
	Path        string
	FileLevel   zapcore.LevelEnabler
	RemoteLevel zapcore.LevelEnabler
	MaxBackups  int
	Compress    bool
	Client      *plugins.Client
}

func New(cfg Config) (l *zap.Logger) {
	// 初始化logger
	remoteConfig := zap.NewProductionEncoderConfig()
	remoteConfig.CallerKey = "source"
	remoteConfig.TimeKey = "timestamp"
	remoteConfig.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	remoteEncoder := zapcore.NewJSONEncoder(remoteConfig)
	remoteWriter := &remoteWriter{
		client: cfg.Client,
	}
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize, // megabytes
		MaxBackups: cfg.MaxBackups,
		Compress:   cfg.Compress, // disabled by default
	})
	core := zapcore.NewTee(
		zapcore.NewSamplerWithOptions(
			zapcore.NewCore(remoteEncoder, remoteWriter, cfg.RemoteLevel), time.Second, 4, 0),
		zapcore.NewSamplerWithOptions(
			zapcore.NewCore(fileEncoder, fileWriter, cfg.FileLevel), time.Second, 4, 0),
	)
	l = zap.New(core, zap.AddCaller())
	return
}
