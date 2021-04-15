package log

import (
	"encoding/json"
	"fmt"

	"github.com/bytedance/Elkeid/agent/global"
)

// ErrorLog describes the log format sent to the server
type ErrorLog struct {
	Level     string `json:"level"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Msg       string `json:"msg"`
}

// LoggerWriter is an empty structure of log hook
type LoggerWriter struct{}

// Implement the corresponding method of the interface
func (*LoggerWriter) Write(p []byte) (n int, err error) {
	l := ErrorLog{}
	e := json.Unmarshal(p, &l)
	if err != nil {
		return 0, e
	}
	m := make(map[string]string)
	m["level"] = l.Level
	m["timestamp"] = l.Timestamp
	m["source"] = l.Source
	m["msg"] = l.Msg
	m["data_type"] = "1001"
	select {
	case global.GrpcChannel <- []*global.Record{{
		Message: m,
	}}:
	default:
		fmt.Println("Channel full")
	}
	return len(p), nil
}
