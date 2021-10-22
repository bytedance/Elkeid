package core

import (
	"errors"
	"sync"

	"github.com/bytedance/Elkeid/agent/proto"
)

var (
	Mu                = &sync.Mutex{}
	Buf               = [8192]interface{}{}
	Offset            = 0
	ErrBufferOverflow = errors.New("buffer overflow")
	hook              func(interface{}) interface{}
	RecordPool        = sync.Pool{
		New: func() interface{} {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, 1024*2),
			}
		},
	}
)

func SetTransmissionHook(fn func(interface{}) interface{}) {
	hook = fn
}
func Transmission(rec interface{}, tolerate bool) (err error) {
	if hook != nil {
		rec = hook(rec)
	}
	Mu.Lock()
	defer Mu.Unlock()
	if Offset < len(Buf) {
		Buf[Offset] = rec
		Offset++
		return
	}
	if tolerate {
		err = ErrBufferOverflow
	} else {
		Buf[0] = rec
	}
	return
}
