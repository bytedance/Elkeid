package main

import (
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/port"
	plugins "github.com/bytedance/plugins"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

type PortHandler struct{}

func (h *PortHandler) Name() string {
	return "port"
}
func (h *PortHandler) DataType() int {
	return 5051
}
func (h *PortHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	ports, err := port.ListeningPorts()
	if err != nil {
		zap.S().Error(err)
	} else {
		for _, port := range ports {
			rec := &plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: make(map[string]string, 15),
				},
			}
			mapstructure.Decode(port, &rec.Data.Fields)
			m, _ := cache.Get(5056, port.Sport)
			rec.Data.Fields["container_id"] = m["container_id"]
			rec.Data.Fields["container_name"] = m["container_name"]
			rec.Data.Fields["package_seq"] = seq
			c.SendRecord(rec)
		}
	}
}
