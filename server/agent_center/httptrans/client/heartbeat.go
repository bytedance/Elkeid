package client

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/levigross/grequests"
	"time"
)

const (
	HBJoinUrl  = "http://%s/api/v1/agent/heartbeat/join/bulk"
	HBEvictUrl = "http://%s/api/v1/agent/heartbeat/evict/bulk"
)

type ConnStat struct {
	AgentInfo   map[string]interface{}   `json:"agent_info"`
	PluginsInfo []map[string]interface{} `json:"plugins_info"`
}

type HeartBeatEvictModel struct {
	AgentID   string `json:"agent_id" bson:"agent_id"`
	AgentAddr string `json:"agent_addr" bson:"agent_addr"`
}

const SendCountWeight = 100

var HBWriter *hbWriter

func init() {
	HBWriter = newHBWriter()
}

type hbWriter struct {
	JoinQueue  chan ConnStat
	EvictQueue chan HeartBeatEvictModel
}

func newHBWriter() *hbWriter {
	w := &hbWriter{}
	w.JoinQueue = make(chan ConnStat, 1024*10)
	w.EvictQueue = make(chan HeartBeatEvictModel, 1024*10)
	go w.runJoin()
	go w.runEvict()
	return w
}

func (w *hbWriter) runJoin() {
	var (
		timer  = time.NewTicker(time.Second * 5)
		writes []ConnStat
	)

	ylog.Infof("hbWriter", "Run")
	for {
		select {
		case tmp := <-w.JoinQueue:
			writes = append(writes, tmp)
		case <-timer.C:
			if len(writes) < 1 {
				continue
			}

			PostHBJoin(writes)
			writes = make([]ConnStat, 0)
		}

		if len(writes) >= SendCountWeight {
			PostHBJoin(writes)
			writes = make([]ConnStat, 0)
		}
	}
}

func (w *hbWriter) runEvict() {
	var (
		timer  = time.NewTicker(time.Second * 5)
		writes []HeartBeatEvictModel
	)

	ylog.Infof("hbWriter", "runEvict")
	for {
		select {
		case tmp := <-w.EvictQueue:
			writes = append(writes, tmp)
		case <-timer.C:
			if len(writes) < 1 {
				continue
			}

			PostHBEvict(writes)
			writes = make([]HeartBeatEvictModel, 0)
		}

		if len(writes) >= SendCountWeight {
			PostHBEvict(writes)
			writes = make([]HeartBeatEvictModel, 0)
		}
	}
}

func (w *hbWriter) Join(v ConnStat) {
	select {
	case w.JoinQueue <- v:
	default:
		ylog.Errorf("hbWriter", "Join channel is full len %d", len(w.JoinQueue))
	}
}

func (w *hbWriter) Evict(v HeartBeatEvictModel) {
	select {
	case w.EvictQueue <- v:
	default:
		ylog.Errorf("hbWriter", "Evict channel is full len %d", len(w.EvictQueue))
	}
}

func PostHBJoin(hb []ConnStat) {
	url := fmt.Sprintf(HBJoinUrl, common.GetRandomManageAddr())
	resp, err := grequests.Post(url, &grequests.RequestOptions{
		JSON:           hb,
		RequestTimeout: 60 * time.Second,
		Headers:        map[string]string{"token": GetToken()},
	})
	if err != nil {
		ylog.Errorf("PostHBJoin", "failed: %s", err.Error())
		return
	}

	if !resp.Ok {
		ylog.Errorf("PostHBJoin", "response code is %d, url is %s, agent len is %d", resp.StatusCode, url, len(hb))
		return
	}

	var response ResTaskConf
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("PostHBJoin", "error: %s, %s", err.Error(), resp.String())
		return
	}
	if response.Code != 0 {
		ylog.Errorf("PostHBJoin", "response is %s, url is %s, agent len is %d", resp.String(), url, len(hb))
	}
}

func PostHBEvict(hb []HeartBeatEvictModel) {
	resp, err := grequests.Post(fmt.Sprintf(HBEvictUrl, common.GetRandomManageAddr()), &grequests.RequestOptions{
		JSON:           hb,
		RequestTimeout: 60 * time.Second,
		Headers:        map[string]string{"token": GetToken()},
	})
	if err != nil {
		ylog.Errorf("PostHBEvict", "failed: %v", err.Error())
		return
	}

	if !resp.Ok {
		ylog.Errorf("PostHBEvict", "response code is %d, agent len is %d", resp.StatusCode, len(hb))
		return
	}

	var response ResTaskConf
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("PostHBEvict", "error: %s, %s", err.Error(), resp.String())
		return
	}
	if response.Code != 0 {
		ylog.Errorf("PostHBEvict", "response code is not 0, %s", resp.String())
		return
	}
	return
}
