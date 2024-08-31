package client

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/levigross/grequests"
	"time"
)

const (
	HBJoinUrl        = "http://%s/api/v1/agent/heartbeat/join/bulk"
	HBEvictUrl       = "http://%s/api/v1/agent/heartbeat/evict/bulk"
	ProxyHBUpdateUrl = "http://%s/api/v1/agent/UpdateProxyHeartbeat"
	SendCountWeight  = 100
)

type ConnStat struct {
	AgentInfo   map[string]interface{}   `json:"agent_info"`
	PluginsInfo []map[string]interface{} `json:"plugins_info"`
}

type HeartBeatEvictModel struct {
	AgentID   string `json:"agent_id" bson:"agent_id"`
	AgentAddr string `json:"agent_addr" bson:"agent_addr"`
}

var HBWriter *hbWriter

func init() {
	HBWriter = newHBWriter()
}

type hbWriter struct {
	JoinQueue  chan ConnStat
	EvictQueue chan HeartBeatEvictModel
}

func newHBWriter() *hbWriter {
	w := &hbWriter{
		JoinQueue:  make(chan ConnStat, 10240),
		EvictQueue: make(chan HeartBeatEvictModel, 10240),
	}
	go w.runJoin()
	go w.runEvict()
	return w
}

func (w *hbWriter) runJoin() {
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()

	// Pre-allocate slice with a reasonable capacity
	writes := make([]ConnStat, 0, SendCountWeight)

	ylog.Infof("hbWriter", "Starting runJoin")

	for {
		select {
		case tmp := <-w.JoinQueue:
			writes = append(writes, tmp)
			if len(writes) >= SendCountWeight {
				if err := w.flushJoin(writes); err != nil {
					ylog.Errorf("hbWriter", "FlushJoin failed: %v", err)
				}
				// Reset slice length to 0 but keep underlying array
				writes = writes[:0]
			}
		case <-timer.C:
			if len(writes) > 0 {
				if err := w.flushJoin(writes); err != nil {
					ylog.Errorf("hbWriter", "FlushJoin failed: %v", err)
				}
				// Reset slice length to 0 but keep underlying array
				writes = writes[:0]
			}
		}
	}
}

func (w *hbWriter) runEvict() {
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()

	// Pre-allocate slice with a reasonable capacity
	writes := make([]HeartBeatEvictModel, 0, SendCountWeight)

	ylog.Infof("hbWriter", "Starting runEvict")

	for {
		select {
		case tmp := <-w.EvictQueue:
			writes = append(writes, tmp)
			if len(writes) >= SendCountWeight {
				if err := w.flushEvict(writes); err != nil {
					ylog.Errorf("hbWriter", "FlushEvict failed: %v", err)
				}
				// Reset slice length to 0 but keep underlying array
				writes = writes[:0]
			}
		case <-timer.C:
			if len(writes) > 0 {
				if err := w.flushEvict(writes); err != nil {
					ylog.Errorf("hbWriter", "FlushEvict failed: %v", err)
				}
				// Reset slice length to 0 but keep underlying array
				writes = writes[:0]
			}
		}
	}
}

func (w *hbWriter) Join(v ConnStat) {
	select {
	case w.JoinQueue <- v:
	default:
		ylog.Errorf("hbWriter", "Join channel is full (len: %d)", len(w.JoinQueue))
	}
}

func (w *hbWriter) Evict(v HeartBeatEvictModel) {
	select {
	case w.EvictQueue <- v:
	default:
		ylog.Errorf("hbWriter", "Evict channel is full (len: %d)", len(w.EvictQueue))
	}
}

func (w *hbWriter) flushJoin(hb []ConnStat) error {
	return PostToServer(HBJoinUrl, hb, len(hb), 60*time.Second)
}

func (w *hbWriter) flushEvict(hb []HeartBeatEvictModel) error {
	return PostToServer(HBEvictUrl, hb, len(hb), 60*time.Second)
}

func PostToServer(urlTemplate string, body interface{}, dataLen int, timeout time.Duration) error {
	url := fmt.Sprintf(urlTemplate, common.GetRandomManageAddr())
	resp, err := grequests.Post(url, &grequests.RequestOptions{
		JSON:           body,
		RequestTimeout: timeout,
		Headers:        map[string]string{"token": GetToken()},
	})
	if err != nil {
		ylog.Errorf("PostToServer", "Request failed: %v", err)
		return err
	}

	if !resp.Ok {
		ylog.Errorf("PostToServer", "Non-OK response: %d, URL: %s, Data Length: %d", resp.StatusCode, url, dataLen)
		return fmt.Errorf("response code is %d", resp.StatusCode)
	}

	var response ResTaskConf
	if err := json.Unmarshal(resp.Bytes(), &response); err != nil {
		ylog.Errorf("PostToServer", "Failed to unmarshal response: %v, Response: %s", err, resp.String())
		return err
	}

	if response.Code != 0 {
		ylog.Errorf("PostToServer", "Non-zero response code: %d, Response: %s", response.Code, resp.String())
		return fmt.Errorf("non-zero response code: %d, response: %s", response.Code, response.Message)
	}

	return nil
}

func UpdateProxyHeartbeat(body pb.HeartbeatRequest) error {
	return PostToServer(ProxyHBUpdateUrl, body, 1, 10*time.Second)
}
