package task

import (
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

const (
	SendTimeWeightSec = 15
	SendCountWeight   = 1000

	KeyAgentHB            = "key_agentHB"
	KeyAgentSubTask       = "key_agentSubTask"
	KeyAgentSubTaskUpdate = "key_agentSubTask_update"
)

var (
	writerMap = make(map[string]DBWriter)
)

type DBWriter interface {
	Init()
	Run()
	Add(interface{})
}

func registerWriter(name string, writer DBWriter) {
	writer.Init()
	writerMap[name] = writer
	go writer.Run()
}

func asyncWrite(key string, value interface{}) {
	if w, ok := writerMap[key]; ok {
		w.Add(value)
	} else {
		ylog.Errorf("AsyncWrite", "%s not found", key)
	}
}

func HBAsyncWrite(value interface{}) {
	if _, ok := writerMap[KeyAgentHB]; !ok {
		registerWriter(KeyAgentHB, &hbWriter{})
	}
	asyncWrite(KeyAgentHB, value)
}

func SubTaskAsyncWrite(value interface{}) {
	if _, ok := writerMap[KeyAgentSubTask]; !ok {
		registerWriter(KeyAgentSubTask, &subTaskWriter{})
	}
	asyncWrite(KeyAgentSubTask, value)
}

func SubTaskUpdateAsyncWrite(value interface{}) {
	if _, ok := writerMap[KeyAgentSubTaskUpdate]; !ok {
		registerWriter(KeyAgentSubTaskUpdate, &subTaskUpdateWriter{})
	}
	asyncWrite(KeyAgentSubTaskUpdate, value)
}
