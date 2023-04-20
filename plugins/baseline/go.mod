module baseline

go 1.16

replace github.com/bytedance/plugins => ../lib/go

require (
	github.com/bytedance/plugins v0.0.0-00010101000000-000000000000
	github.com/spf13/viper v1.4.0
	gopkg.in/yaml.v2 v2.4.0
)
