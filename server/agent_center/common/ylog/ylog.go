package ylog

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"time"
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

func NewYLog(opts ...Option) *YLog {
	options := &Options{}
	for _, opt := range opts {
		opt(options)
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
	if options.MaxBackups != 0 {
		maxBackups = options.MaxBackups
	}
	logLevel := zapcore.Level(options.Level)

	hook := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
		LocalTime:  true,
		Compress:   true,
	}

	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		TimeKey:        "ts",
		CallerKey:      "caller",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     CustomTimeEncoder, // Use custom time encoder
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), zapcore.AddSync(hook)),
		logLevel,
	)

	return &YLog{provider: zap.New(core), lvl: options.Level}
}

// Custom time encoder that formats time as both Unix timestamp and a readable format
func CustomTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	// Append Human-readable time
	enc.AppendString(t.Format("2006-01-02 15:04:05"))
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
		defaultLogger.provider.Fatal(msg, zap.String("info", fmt.Sprintf(format, v...)), zap.Stack("stacktrace"))
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
