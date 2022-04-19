package buffer

import (
	"errors"
	"sync"

	"github.com/bytedance/Elkeid/agent/proto"
)

var (
	mu                = &sync.Mutex{}
	buf               = [8192]*proto.EncodedRecord{}
	offset            = 0
	ErrbufferOverflow = errors.New("buffer overflow")
	hook              func(interface{}) interface{}
)

func SetTransmissionHook(fn func(interface{}) interface{}) {
	hook = fn
}
func WriteEncodedRecord(rec *proto.EncodedRecord) (err error) {
	if hook != nil {
		rec = hook(rec).(*proto.EncodedRecord)
	}
	mu.Lock()
	if offset < len(buf) {
		buf[offset] = rec
		offset++
	}
	mu.Unlock()
	return
}
func WriteRecord(rec *proto.Record) (err error) {
	erec := GetEncodedRecord()
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
