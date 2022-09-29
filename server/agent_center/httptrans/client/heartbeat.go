package client

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/levigross/grequests"
	"time"
)

const HBJoinUrl = "http://%s/api/v1/agent/heartbeat/join"
const HBEvictUrl = "http://%s/api/v1/agent/heartbeat/evict"

type ConnStat struct {
	AgentInfo   map[string]interface{}   `json:"agent_info"`
	PluginsInfo []map[string]interface{} `json:"plugins_info"`
}

type HeartBeatEvictModel struct {
	AgentID   string `json:"agent_id" bson:"agent_id"`
	AgentAddr string `json:"agent_addr" bson:"agent_addr"`
}

func PostHBJoin(hb *ConnStat) {
	url := fmt.Sprintf(HBJoinUrl, common.GetRandomManageAddr())
	resp, err := grequests.Post(url, &grequests.RequestOptions{
		JSON:           *hb,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		ylog.Errorf("PostHBJoin", "failed: %v", err)
		return
	}

	if !resp.Ok {
		ylog.Errorf("PostHBJoin", "response code is %d, %s, %#v", resp.StatusCode, url, *hb)
		return
	}

	var response ResTaskConf
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("PostHBJoin", "error: %s, %s", err.Error(), resp.String())
		return
	}
	if response.Code != 0 {
		ylog.Errorf("PostHBJoin", "response code is not 0, %s", resp.String())
		return
	}
}

func PostHBEvict(hb *HeartBeatEvictModel) {
	resp, err := grequests.Post(fmt.Sprintf(HBEvictUrl, common.GetRandomManageAddr()), &grequests.RequestOptions{
		JSON:           *hb,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		ylog.Errorf("PostHBEvict", "failed: %v\n", err)
		return
	}

	if !resp.Ok {
		ylog.Errorf("PostHBEvict", "response code is %d, %#v", resp.StatusCode, *hb)
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
}
