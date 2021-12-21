package task

import (
	"sync"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

const (
	SendTimeWeightSec = 15
	SendCountWeight   = 1000

	KeyAgentHB            = "key_agentHB"
	KeyAgentV2HB          = "key_agentV2HB"
	KeyAgentSubTask       = "key_agentSubTask"
	KeyAgentSubTaskUpdate = "key_agentSubTask_update"
	KeyHubStatusUpdate    = "key_hub_status_update"
	KeyHubAlarmUpdate     = "key_hub_alarm"
	KeyTraceRawDataUpdate = "key_trace_rawdata"
	KeyHubAssetUpdate     = "key_hub_asset"
	KeySystemAlertUpdate  = "key_system_alert"
	KeyLeaderVulnUpdate   = "key_leader_vuln"
)

var (
	writerMap  = make(map[string]DBWriter)
	writerLock sync.RWMutex

	AgentHBOnce            sync.Once
	AgentV2HBOnce          sync.Once
	AgentSubTaskOnce       sync.Once
	AgentSubTaskUpdateOnce sync.Once
	HubStatusUpdateOnce    sync.Once
	HubAlarmOnce           sync.Once
	TraceRawDataOnce       sync.Once
	HubAssetOnce           sync.Once
	SystemAlertOnce        sync.Once
	LeaderVulnOnce         sync.Once
)

type DBWriter interface {
	Init()
	Run()
	Add(interface{})
}

func registerWriter(name string, writer DBWriter) {
	writer.Init()
	writerLock.Lock()
	writerMap[name] = writer
	writerLock.Unlock()
	go writer.Run()
}

func asyncWrite(key string, value interface{}) {
	writerLock.RLock()
	if w, ok := writerMap[key]; ok {
		writerLock.RUnlock()
		w.Add(value)
	} else {
		writerLock.RUnlock()
		ylog.Errorf("AsyncWrite", "%s not found", key)
	}
}

func HBAsyncWrite(value interface{}) {
	AgentHBOnce.Do(func() {
		registerWriter(KeyAgentHB, &hbWriter{})
	})

	asyncWrite(KeyAgentHB, value)
}

func HBV2AsyncWrite(value interface{}) {
	AgentV2HBOnce.Do(func() {
		registerWriter(KeyAgentV2HB, &hbV2Writer{})
	})

	asyncWrite(KeyAgentV2HB, value)
}

func SubTaskAsyncWrite(value interface{}) {
	AgentSubTaskOnce.Do(func() {
		registerWriter(KeyAgentSubTask, &subTaskWriter{})
	})

	asyncWrite(KeyAgentSubTask, value)
}

func SubTaskUpdateAsyncWrite(value interface{}) {
	AgentSubTaskUpdateOnce.Do(func() {
		registerWriter(KeyAgentSubTaskUpdate, &subTaskUpdateWriter{})
	})

	asyncWrite(KeyAgentSubTaskUpdate, value)
}

func HubAlarmAsyncWrite(value interface{}) {
	HubAlarmOnce.Do(func() {
		registerWriter(KeyHubAlarmUpdate, &hubAlarmWriter{})
	})

	asyncWrite(KeyHubAlarmUpdate, value)
}

func TraceRawDataAsyncWrite(value interface{}) {
	TraceRawDataOnce.Do(func() {
		registerWriter(KeyTraceRawDataUpdate, &traceRawDataWriter{})
	})

	asyncWrite(KeyTraceRawDataUpdate, value)
}

func HubAssetAsyncWrite(value interface{}) {
	HubAssetOnce.Do(func() {
		registerWriter(KeyHubAssetUpdate, &hubAssetWriter{})
	})

	asyncWrite(KeyHubAssetUpdate, value)
}

func HubSystemAlertAsyncWrite(value interface{}) {
	SystemAlertOnce.Do(func() {
		registerWriter(KeySystemAlertUpdate, &sysAlertWriter{})
	})

	asyncWrite(KeySystemAlertUpdate, value)
}

func LeaderVulnAsyncWrite(value interface{}) {
	LeaderVulnOnce.Do(func() {
		registerWriter(KeyLeaderVulnUpdate, &leaderVulnWriter{})
	})

	asyncWrite(KeyLeaderVulnUpdate, value)
}
