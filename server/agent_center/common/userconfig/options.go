package userconfig

type Options struct {
	Path string
}

type Option func(opts *Options)

func WithPath(path string) Option {
	return func(opts *Options) {
		opts.Path = path
	}
}
