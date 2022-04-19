package log

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/agent/buffer"
	"github.com/bytedance/Elkeid/agent/proto"
)

type GrpcWriter struct {
}

func (w *GrpcWriter) Write(p []byte) (n int, err error) {
	rec := &proto.Record{
		DataType: 1010,
		Data: &proto.Payload{
			Fields: map[string]string{},
		},
	}
	fields := map[string]interface{}{}
	err = json.Unmarshal(p, &fields)
	if err != nil {
		return
	}
	timestamp, ok := fields["timestamp"]
	if ok {
		timestamp, err := strconv.ParseInt(timestamp.(string), 10, 64)
		if err == nil {
			rec.Timestamp = timestamp
			delete(fields, "timestamp")
		}
	}
	if rec.Timestamp == 0 {
		rec.Timestamp = time.Now().Unix()
	}
	for k, v := range fields {
		switch v := v.(type) {
		case string:
			rec.Data.Fields[k] = v
		case int:
			rec.Data.Fields[k] = strconv.Itoa(v)
		}
	}
	err = buffer.WriteRecord(rec)
	if err != nil {
		return
	}
	n = len(p)
	return
}

func (w *GrpcWriter) Sync() error {
	return nil
}
