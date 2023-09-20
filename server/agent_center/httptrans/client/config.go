package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/levigross/grequests"
	"time"
)

const (
	ConfigUrl             = `http://%s/api/v6/component/GetComponentInstances`
	TagsUrl               = `http://%s/api/v1/agent/queryInfo`
	CheckCommonConfigUrl  = `http://%s/api/v6/investigate/auto_defense/CheckAgentConfig`
	VerifyCommonConfigUrl = `http://%s/api/v6/investigate/auto_defense/VerifyAgentConfigRelease`
)

type ResAgentConf struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    []ConfigMsg `json:"data"`
}

type ConfigMsg struct {
	Name        string   `json:"name,omitempty"`
	Type        string   `json:"type,omitempty"`
	Signature   string   `json:"signature,omitempty"`
	Version     string   `json:"version,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	DownloadURL []string `json:"download_url,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}

type AgentExtraInfo struct {
	Tags     string `json:"tags"`
	PSMName  string `json:"psm_name"`
	PSMPath  string `json:"psm_path"`
	Enhanced string `json:"enhanced"`
}

type ResAgentTags struct {
	Code    int                       `json:"code"`
	Message string                    `json:"msg"`
	Data    map[string]AgentExtraInfo `json:"data"`
}

func GetConfigFromRemote(agentID string, detail map[string]interface{}) ([]*pb.ConfigItem, error) {
	rOption := &grequests.RequestOptions{
		JSON: detail,
	}
	resp, err := grequests.Post(fmt.Sprintf(ConfigUrl, common.GetRandomManageAddr()), rOption)
	if err != nil {
		ylog.Errorf("GetConfigFromRemote", "error %s %s", agentID, err.Error())
		return nil, err
	}
	if !resp.Ok {
		ylog.Errorf("GetConfigFromRemote", "response code is not 200, AgentID: %s, StatusCode: %d,String: %s", agentID, resp.StatusCode, resp.String())
		return nil, errors.New("status code is not ok")
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
			Type:        v.Type,
			Version:     v.Version,
			SHA256:      v.SHA256,
			Signature:   v.Signature,
			DownloadURL: v.DownloadURL,
			Detail:      v.Detail,
		}
		res = append(res, tmp)
	}
	return res, nil
}

func GetExtraInfoFromRemote(idList []string) (map[string]AgentExtraInfo, error) {
	res := map[string]AgentExtraInfo{}
	resp, err := grequests.Post(fmt.Sprintf(TagsUrl, common.GetRandomManageAddr()),
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

type ResCheckCommonConfig struct {
	Code    int                           `json:"code"`
	Message string                        `json:"msg"`
	Data    *common.ConfigRefreshResponse `json:"data"`
}

func CheckCommonConfig(fp *pb.ConfigRefreshRequest) (*common.ConfigRefreshResponse, error) {
	rOption := &grequests.RequestOptions{
		JSON: fp,
	}
	rOption.RequestTimeout = 15 * time.Second
	resp, err := grequests.Post(fmt.Sprintf(CheckCommonConfigUrl, common.GetRandomManageAddr()), rOption)
	if err != nil {
		ylog.Errorf("CheckCommonConfig", "error %s %s %s", fp.AgentID, fp.PluginName, err.Error())
		return nil, err
	}
	if !resp.Ok {
		ylog.Errorf("CheckCommonConfig", "response code is not 200, AgentID: %s, StatusCode: %d,String: %s", fp.AgentID, resp.StatusCode, resp.String())
		return nil, errors.New("status code is not ok")
	}

	var res = &common.Response{}
	err = json.Unmarshal(resp.Bytes(), res)
	if err != nil {
		ylog.Errorf("CheckCommonConfig", "agentID: %s, error: %s, resp:%s", fp.AgentID, err.Error(), resp.String())
		return nil, err
	}

	if res.Code != 0 {
		ylog.Errorf("CheckCommonConfig", "response code is not 0, agentID: %s, resp: %s", fp.AgentID, resp.String())

		//返回空值
		return &common.ConfigRefreshResponse{
			AgentID:    fp.AgentID,
			PluginName: fp.PluginName,
			SecretKey:  "",
			Version:    "",
			Release:    0,
			Status:     0,
			Config:     make([]*pb.ConfigDetail, 0),
		}, nil
	}

	var resConfig = &ResCheckCommonConfig{}
	err = json.Unmarshal(resp.Bytes(), resConfig)
	if err != nil {
		ylog.Errorf("CheckCommonConfig", "agentID: %s, error: %s, resp:%s", fp.AgentID, err.Error(), resp.String())
		return nil, err
	}
	return resConfig.Data, nil
}

type ResVerifyCommonConfig struct {
	Code    int                         `json:"code"`
	Message string                      `json:"msg"`
	Data    []*common.ConfigReleaseInfo `json:"data"`
}

func VerifyCommonConfigRelease(ri []*common.ConfigReleaseInfo) ([]*common.ConfigReleaseInfo, error) {
	rOption := &grequests.RequestOptions{
		JSON: ri,
	}
	rOption.RequestTimeout = 15 * time.Second
	resp, err := grequests.Post(fmt.Sprintf(VerifyCommonConfigUrl, common.GetRandomManageAddr()), rOption)
	if err != nil {
		ylog.Errorf("VerifyCommonConfigRelease", "error %s", err.Error())
		return nil, err
	}
	if !resp.Ok {
		ylog.Errorf("VerifyCommonConfigRelease", "response code is not 200, StatusCode: %d,String: %s", resp.StatusCode, resp.String())
		return nil, errors.New("status code is not ok")
	}

	var res = &common.Response{}
	err = json.Unmarshal(resp.Bytes(), res)
	if err != nil {
		ylog.Errorf("VerifyCommonConfigRelease", "error: %s, resp:%s", err.Error(), resp.String())
		return nil, err
	}
	if res.Code != 0 {
		ylog.Errorf("VerifyCommonConfigRelease", "response code is not 0, resp: %s", resp.String())
		return nil, errors.New("response code is not 0")
	}

	var resConfig = &ResVerifyCommonConfig{}
	err = json.Unmarshal(resp.Bytes(), resConfig)
	if err != nil {
		ylog.Errorf("VerifyCommonConfigRelease", "error: %s, resp:%s", err.Error(), resp.String())
		return nil, err
	}
	return resConfig.Data, nil
}
