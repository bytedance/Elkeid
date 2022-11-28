package agent

import (
	"encoding/json"
	"sync"
)

type StateType int32

const (
	StateTypeRunning StateType = iota
	StateTypeAbnormal
	// StateTypeSyncing
)

var stateTypeMap = map[StateType]string{
	StateTypeRunning: "running",
	// StateTypeSyncing:  "syncing",
	StateTypeAbnormal: "abnormal",
}
var (
	mu           = &sync.Mutex{}
	currentState = StateTypeRunning
	abnormalErrs = []string{}
)

func (x StateType) String() string {
	return stateTypeMap[x]
}

//	func Sync() {
//		mu.Lock()
//		defer mu.Unlock()
//		currentState = StateTypeSyncing
//		abnormalErrs = []string{}
//	}
func SetRunning() {
	mu.Lock()
	defer mu.Unlock()
	currentState = StateTypeRunning
	abnormalErrs = []string{}
}
func SetAbnormal(err string) {
	mu.Lock()
	defer mu.Unlock()
	currentState = StateTypeAbnormal
	abnormalErrs = append(abnormalErrs, err)
}

func State() (string, string) {
	mu.Lock()
	defer mu.Unlock()
	err, _ := json.Marshal(abnormalErrs)
	return currentState.String(), string(err)
}
