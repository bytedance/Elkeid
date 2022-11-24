package dbtask

import (
	"sync"

	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
)

const (
	SendTimeWeightSec = 15
	SendCountWeight   = 1000
	channelSize       = 1024 * 4

	KeyAgentHB              = "key_agentHB"
	KeyAgentSubTask         = "key_agentSubTask"
	KeyAgentSubTaskUpdate   = "key_agentSubTask_update"
	KeyHubAlarmUpdate       = "key_hub_alarm"
	KeyHubAssetUpdate       = "key_hub_asset"
	KeyLeaderVulnUpdate     = "key_leader_vuln"
	KeyLeaderBaselineUpdate = "key_leader_baseline"
	KeyLeaderRaspUpdate     = "key_leader_rasp"
	KeyRaspAlarmUpdate      = "key_rasp_alarm"
	KeyKubeAlarmUpdate      = "key_kube_alarm"

	KeyVirusDetectionUpdate = "key_virus_detection"
)

var (
	writerMap  = make(map[string]DBWriter)
	writerLock sync.RWMutex

	AgentHBOnce            sync.Once
	AgentSubTaskOnce       sync.Once
	AgentSubTaskUpdateOnce sync.Once
	HubAlarmOnce           sync.Once
	HubAssetOnce           sync.Once
	LeaderVulnOnce         sync.Once
	LeaderBaselineOnce     sync.Once
	LeaderRaspOnce         sync.Once
	RaspAlarmOnce          sync.Once
	KubeAlarmOnce          sync.Once
	VirusDetectionOne      sync.Once
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

func HubAssetAsyncWrite(value interface{}) {
	HubAssetOnce.Do(func() {
		registerWriter(KeyHubAssetUpdate, &hubAssetWriter{})
	})

	asyncWrite(KeyHubAssetUpdate, value)
}

func LeaderVulnAsyncWrite(value interface{}) {
	LeaderVulnOnce.Do(func() {
		registerWriter(KeyLeaderVulnUpdate, &leaderVulnWriter{})
	})

	asyncWrite(KeyLeaderVulnUpdate, value)
}

func LeaderBaselineAsyncWrite(value interface{}) {
	LeaderBaselineOnce.Do(func() {
		registerWriter(KeyLeaderBaselineUpdate, &leaderBaselineWriter{})
	})

	asyncWrite(KeyLeaderBaselineUpdate, value)
}

func LeaderRaspAsyncWrite(value interface{}) {
	LeaderRaspOnce.Do(func() {
		registerWriter(KeyLeaderRaspUpdate, &leaderRaspWriter{})
	})

	asyncWrite(KeyLeaderRaspUpdate, value)
}

func RaspAlarmAsyncWrite(value interface{}) {
	RaspAlarmOnce.Do(func() {
		registerWriter(KeyRaspAlarmUpdate, &raspAlarmWriter{})
	})

	asyncWrite(KeyRaspAlarmUpdate, value)
}

func KubeAlarmAsyncWrite(value interface{}) {
	KubeAlarmOnce.Do(func() {
		registerWriter(KeyKubeAlarmUpdate, &kubeAlarmWriter{})
	})

	asyncWrite(KeyKubeAlarmUpdate, value)
}

func VirusDetectionAsyncWrite(value interface{}) {
	VirusDetectionOne.Do(func() {
		registerWriter(KeyVirusDetectionUpdate, &virusDetectionWriter{})
	})

	asyncWrite(KeyVirusDetectionUpdate, value)
}
