package main

import (
	"bufio"
	"os"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/engine"
	plugins "github.com/bytedance/plugins"
)

type KmodHandler struct{}

func (*KmodHandler) Name() string {
	return "kmod"
}
func (*KmodHandler) DataType() int {
	return 5062
}
func (h *KmodHandler) Handle(c *plugins.Client, cache *engine.Cache, seq string) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 5 {
			c.SendRecord(&plugins.Record{
				DataType:  int32(h.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &plugins.Payload{
					Fields: map[string]string{
						"name":        fields[0],
						"size":        fields[1],
						"refcount":    fields[2],
						"used_by":     fields[3],
						"state":       fields[4],
						"addr":        fields[5],
						"package_seq": seq,
					},
				},
			})
		}
	}

}
