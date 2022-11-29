package main

import (
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	"github.com/bytedance/Elkeid/plugins/collector/process"
	plugins "github.com/bytedance/plugins"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

type ProcessHandler struct{}

func (h ProcessHandler) Name() string {
	return "process"
}
func (h ProcessHandler) DataType() int {
	return 5050
}

func (h *ProcessHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	procs, err := process.Processes(false)
	if err != nil {
		zap.S().Error(err)
	} else {
		for _, p := range procs {
			time.Sleep(process.TraversalInterval)
			cmdline, err := p.Cmdline()
			if err != nil {
				continue
			}
			stat, err := p.Stat()
			if err != nil {
				continue
			}
			status, err := p.Status()
			if err != nil {
				continue
			}
			ns, _ := p.Namespaces()
			rec := &plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: make(map[string]string, 40),
				},
			}
			rec.Data.Fields["cmdline"] = cmdline
			rec.Data.Fields["cwd"], _ = p.Cwd()
			rec.Data.Fields["checksum"], _ = p.ExeChecksum()
			rec.Data.Fields["exe_hash"], _ = p.ExeHash()
			rec.Data.Fields["exe"], _ = p.Exe()
			rec.Data.Fields["pid"] = p.Pid()
			mapstructure.Decode(stat, &rec.Data.Fields)
			mapstructure.Decode(status, &rec.Data.Fields)
			mapstructure.Decode(ns, &rec.Data.Fields)
			m, _ := cache.Get(5056, ns.Pid)
			rec.Data.Fields["container_id"] = m["container_id"]
			rec.Data.Fields["container_name"] = m["container_name"]
			rec.Data.Fields["integrity"] = "true"
			// only for host files
			if _, ok := cache.Get(5057, rec.Data.Fields["exe"]); ok && rec.Data.Fields["container_id"] == "" {
				rec.Data.Fields["integrity"] = "false"
			}
			rec.Data.Fields["package_seq"] = seq
			c.SendRecord(rec)
		}
	}
}
