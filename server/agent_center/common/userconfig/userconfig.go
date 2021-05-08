package userconfig

import (
	"github.com/spf13/viper"
)

func NewUserConfig(opts ...interface{}) (*viper.Viper, error) {

	var (
		options *Options
		opt     interface{}
		v       *viper.Viper
		err     error
	)

	options = &Options{}
	for _, opt = range opts {
		opt.(Option)(options)
	}

	v = viper.New()

	v.SetConfigFile(options.Path)

	if err = v.ReadInConfig(); err != nil {
		return nil, err
	}

	return v, nil
}
