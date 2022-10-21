package log

import (
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/agent/buffer"
	"github.com/bytedance/Elkeid/agent/proto"
)

func ErrorWithToken(token string, args ...interface{}) {
	buffer.WriteRecord(
		&proto.Record{
			DataType:  5100,
			Timestamp: time.Now().Unix(),
			Data: &proto.Payload{
				Fields: map[string]string{
					"token":  token,
					"msg":    fmt.Sprint(args...),
					"status": "failed",
				},
			},
		},
	)
}
func ErrorfWithToken(token string, format string, args ...interface{}) {
	buffer.WriteRecord(
		&proto.Record{
			DataType:  5100,
			Timestamp: time.Now().Unix(),
			Data: &proto.Payload{
				Fields: map[string]string{
					"token":  token,
					"msg":    fmt.Sprintf(format, args...),
					"status": "failed",
				},
			},
		},
	)
}
