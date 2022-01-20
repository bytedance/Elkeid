module collector

go 1.16

replace github.com/bytedance/plugins => ../lib/go

require (
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/bytedance/plugins v1.0.0
	github.com/deckarep/golang-set v1.8.0
	github.com/go-logr/zapr v1.2.2
	github.com/hashicorp/golang-lru v0.5.4
	github.com/karrick/godirwalk v1.16.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/robfig/cron/v3 v3.0.1
	github.com/tklauser/go-sysconf v0.3.9
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.20.0
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
