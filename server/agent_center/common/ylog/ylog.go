package ylog

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
)

const (
	defaultLogFile    = "./default.log"
	defaultMaxSize    = 5
	defaultMaxAge     = 3
	defaultMaxBackups = 3
)

var defaultLogger *YLog

func InitLogger(logger *YLog) {
	defaultLogger = logger
}

// Logger
type YLog struct {
	provider *zap.Logger
	msg      string
	lvl      int
}

func NewYLog(opts ...interface{}) *YLog {
	var (
		opt     interface{}
		options *Options
	)

	options = &Options{}
	for _, opt = range opts {
		opt.(Option)(options)
	}

	logFile := defaultLogFile
	if options.LogFile != "" {
		logFile = options.LogFile
	}
	maxSize := defaultMaxSize
	if options.MaxSize != 0 {
		maxSize = options.MaxSize
	}
	maxAge := defaultMaxAge
	if options.MaxAge != 0 {
		maxAge = options.MaxAge
	}
	maxBackups := defaultMaxBackups
	if options.MaxSize != 0 {
		maxBackups = options.MaxBackups
	}
	logLevel := options.Level

	hook := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
		LocalTime:  false,
		Compress:   false,
	}

	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout),
			zapcore.AddSync(hook)),
		zapcore.Level(logLevel))
	return &YLog{provider: zap.New(core), lvl: logLevel}
}

func (l *YLog) SetMsg(msg string) {
	l.msg = msg
}

func (l *YLog) Print(v ...interface{}) {
	l.provider.Info(l.msg, zap.Any("info", v))
}

func (l *YLog) Printf(format string, v ...interface{}) {
	l.provider.Info(l.msg, zap.Any("info", fmt.Sprintf(format, v...)))
}

func (l *YLog) Println(v ...interface{}) {
	l.provider.Info(l.msg, zap.Any("info", v))
}

func Fatalf(msg string, format string, v ...interface{}) {
	if defaultLogger == nil {
		fmt.Printf(format+"\n", v...)
		return
	}
	if defaultLogger.lvl <= FatalLevel {
		defaultLogger.provider.Fatal(msg, zap.String("info", fmt.Sprintf(format, v...)))
	}
}

func Errorf(msg string, format string, v ...interface{}) {
	if defaultLogger == nil {
		fmt.Printf(format+"\n", v...)
		return
	}
	if defaultLogger.lvl <= ErrorLevel {
		defaultLogger.provider.Error(msg, zap.String("info", fmt.Sprintf(format, v...)))
	}
}

func Warnf(msg string, format string, v ...interface{}) {
	if defaultLogger == nil {
		fmt.Printf(format+"\n", v...)
		return
	}
	if defaultLogger.lvl <= WarnLevel {
		defaultLogger.provider.Warn(msg, zap.String("info", fmt.Sprintf(format, v...)))
	}
}

func Infof(msg string, format string, v ...interface{}) {
	if defaultLogger == nil {
		fmt.Printf(format+"\n", v...)
		return
	}
	if defaultLogger.lvl <= InfoLevel {
		defaultLogger.provider.Info(msg, zap.String("info", fmt.Sprintf(format, v...)))
	}
}

func Debugf(msg string, format string, v ...interface{}) {
	if defaultLogger == nil {
		//fmt.Printf(format+"\n", v...)
		return
	}
	if defaultLogger.lvl <= DebugLevel {
		defaultLogger.provider.Debug(msg, zap.String("info", fmt.Sprintf(format, v...)))
	}
}
