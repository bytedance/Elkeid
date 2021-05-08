package libmongoose

import (
	"encoding/json"
)

// ErrorLog describes the log format sent to the server
type ErrorLog struct {
	Level     string `json:"level"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Plugin    string `json:"plugin"`
	Msg       string `json:"msg"`
}

// LoggerWriter is an empty structure of log hook
type LoggerWriter struct {
	Client *Client
}

// Implement the corresponding method of the interface
func (w *LoggerWriter) Write(p []byte) (n int, err error) {
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
	m["data_type"] = "1002"
	m["plugin"] = w.Client.name
	w.Client.Send(Data{m})
	return len(p), nil
}
