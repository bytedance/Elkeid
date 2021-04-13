package ylog

type Options struct {
	LogFile    string
	MaxSize    int
	MaxAge     int
	MaxBackups int
	Level      int
}

const (
	DebugLevel int = iota - 1
	InfoLevel
	WarnLevel
	ErrorLevel
	DPanicLevel
	PanicLevel
	FatalLevel
)

type Option func(opts *Options)

func WithLogFile(logFile string) Option {
	return func(opts *Options) {
		opts.LogFile = logFile
	}
}

func WithMaxSize(maxSize int) Option {
	return func(opts *Options) {
		opts.MaxSize = maxSize
	}
}

func WithMaxAge(maxAge int) Option {
	return func(opts *Options) {
		opts.MaxAge = maxAge
	}
}

func WithMaxBackups(maxBackups int) Option {
	return func(opts *Options) {
		opts.MaxBackups = maxBackups
	}
}

func WithLevel(level int) Option {
	return func(opts *Options) {
		opts.Level = level
	}
}
