package buffer

import (
	"sync"

	"github.com/bytedance/Elkeid/agent/proto"
)

var (
	mu     = &sync.Mutex{}
	buf    = [2048]*proto.EncodedRecord{}
	offset = 0
	hook   func(any) any
)

func SetTransmissionHook(fn func(any) any) {
	hook = fn
}
func WriteEncodedRecord(rec *proto.EncodedRecord) {
	if hook != nil {
		rec = hook(rec).(*proto.EncodedRecord)
	}
	mu.Lock()
	if offset < len(buf) {
		buf[offset] = rec
		offset++
	} else {
		PutEncodedRecord(rec)
	}
	mu.Unlock()
}
func WriteRecord(rec *proto.Record) (err error) {
	erec := GetEncodedRecord(rec.Data.Size())
	erec.DataType = rec.DataType
	erec.Timestamp = rec.Timestamp
	if cap(erec.Data) < rec.Data.Size() {
		erec.Data = make([]byte, rec.Data.Size())
	} else {
		erec.Data = erec.Data[:rec.Data.Size()]
	}
	_, err = rec.Data.MarshalTo(erec.Data)
	if err != nil {
		return
	}
	mu.Lock()
	if offset < len(buf) {
		buf[offset] = erec
		offset++
	} else {
		// steal it
		buf[0] = erec
	}
	mu.Unlock()
	return
}

func ReadEncodedRecords() (ret []*proto.EncodedRecord) {
	mu.Lock()
	ret = make([]*proto.EncodedRecord, offset)
	copy(ret, buf[:offset])
	offset = 0
	mu.Unlock()
	return
}
