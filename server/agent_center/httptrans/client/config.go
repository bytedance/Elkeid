package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/levigross/grequests"
)

const ConfigUrl = `http://%s/api/v1/agent/getConfig/%s`

type ResAgentConf struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    []ConfigMsg `json:"data"`
}

type ConfigMsg struct {
	Name        string   `json:"name,omitempty"`
	Version     string   `json:"version,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	DownloadURL []string `json:"download_url,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}

func GetConfigFromRemote(agentID string) ([]*pb.ConfigItem, error) {
	resp, err := grequests.Get(fmt.Sprintf(ConfigUrl, getRandomManageAddr(), agentID), nil)
	if err != nil {
		ylog.Errorf("GetConfigFromRemote", "error %s %s", agentID, err.Error())
		return nil, err
	}

	if !resp.Ok {
		ylog.Errorf("GetConfigFromRemote", "response code is not 200, %s %d", agentID, resp.StatusCode)
		return nil, errors.New("status code is not 200")
	}
	var response ResAgentConf
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("GetConfigFromRemote", "agentID: %s, error: %s, resp:%s", agentID, err.Error(), resp.String())
		return nil, err
	}
	if response.Code != 0 {
		ylog.Errorf("GetConfigFromRemote", "response code is not 0, agentID: %s, resp: %s", agentID, resp.String())
		return nil, errors.New("response code is not 0")
	}

	res := make([]*pb.ConfigItem, 0)
	for _, v := range response.Data {
		tmp := &pb.ConfigItem{
			Name:        v.Name,
			Version:     v.Version,
			DownloadURL: v.DownloadURL,
			SHA256:      v.SHA256,
			Detail:      v.Detail,
		}
		res = append(res, tmp)
	}
	return res, nil
}
