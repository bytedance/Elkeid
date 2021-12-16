package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/levigross/grequests"
)

const (
	ConfigUrl = `http://%s/api/v1/agent/getConfig/%s`
	TagsUrl   = `%s/api/v1/agent/queryInfo`
)

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

type AgentExtraInfo struct {
	Tags    string `json:"tags"`
	PSMName string `json:"psm_name"`
	PSMPath string `json:"psm_path"`
}

type ResAgentTags struct {
	Code    int                       `json:"code"`
	Message string                    `json:"msg"`
	Data    map[string]AgentExtraInfo `json:"data"`
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

func GetExtraInfoFromRemote(idList []string) (map[string]AgentExtraInfo, error) {
	res := map[string]AgentExtraInfo{}
	resp, err := grequests.Post(fmt.Sprintf(TagsUrl, getRandomManageAddr()),
		&grequests.RequestOptions{JSON: map[string][]string{"id_list": idList}})
	if err != nil {
		ylog.Errorf("GetExtraInfoFromRemote", "GetExtraInfoFromRemote Post Error, %s", err.Error())
		return res, err
	}

	if !resp.Ok {
		ylog.Errorf("GetExtraInfoFromRemote", "response code is not 200 but %d", resp.StatusCode)
		return res, errors.New("status code is not ok")
	}
	var response ResAgentTags
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("GetExtraInfoFromRemote", "GetExtraInfoFromRemote Error, %s ", resp.String())
		return res, err
	}
	if response.Code != 0 {
		ylog.Errorf("GetExtraInfoFromRemote", "response code is not 0, %s %s ", resp.String())
		return res, errors.New("response code is not 0")
	}
	return response.Data, nil
}
