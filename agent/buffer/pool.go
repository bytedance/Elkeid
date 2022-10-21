package buffer

import (
	"sync"

	"github.com/bytedance/Elkeid/agent/proto"
)

var (
	pool = sync.Pool{
		New: func() interface{} {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, 1024*2),
			}
		},
	}
)

func GetEncodedRecord() *proto.EncodedRecord {
	return pool.Get().(*proto.EncodedRecord)
}
func PutEncodedRecord(rec *proto.EncodedRecord) {
	pool.Put(rec)
}
func PutEncodedRecords(recs []*proto.EncodedRecord) {
	for _, rec := range recs {
		rec.Data = rec.Data[:0]
		pool.Put(rec)
	}
}
