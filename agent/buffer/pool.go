package buffer

import (
	"sync"

	"github.com/bytedance/Elkeid/agent/proto"
)

const (
	defaultCap = 1 << 10
)

var (
	pools = [...]sync.Pool{
		{New: func() any {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, defaultCap),
			}
		}},
		{New: func() any {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, defaultCap*2),
			}
		}}, {New: func() any {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, defaultCap*3),
			}
		}},
		{New: func() any {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, defaultCap*4),
			}
		}},
	}
)

// 0 < size <= 1024 -> chunk 0
// 1024 < size <= 2048 -> chunk 1
// 2048 < size <= 3072 -> chunk 2
// 3072 < size <= 4096 -> chunk 3
func GetEncodedRecord(size int) *proto.EncodedRecord {
	var index int
	if size > 0 {
		index = (size - 1) >> 10
		if index >= len(pools) {
			index = len(pools) - 1
		}
	}
	return pools[index].Get().(*proto.EncodedRecord)
}

func PutEncodedRecord(rec *proto.EncodedRecord) {
	size := cap(rec.Data)
	var index int
	if size > 0 {
		index = (size - 1) >> 10
		if index >= len(pools) {
			return
		}
	}
	rec.Data = rec.Data[:0]
	pools[index].Put(rec)
}
