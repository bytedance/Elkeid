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
	ConfigUrl             = `http://%s/api/v6/component/DescribeHostPolicy`
	TagsUrl               = `http://%s/api/v1/agent/queryInfo`
	CheckCommonConfigUrl  = `http://%s/api/v6/investigate/auto_defense/CheckAgentConfig`
	VerifyCommonConfigUrl = `http://%s/api/v6/investigate/auto_defense/VerifyAgentConfigRelease`
	IaasInfoUrl           = `http://%s/api/v1/asset/getVolcInstance`
)

type ResAgentConf struct {
	Code    int             `json:"code"`
	Message string          `json:"msg"`
	Data    json.RawMessage `json:"data"`
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
		JSON:    detail,
		Headers: map[string]string{"token": GetToken()},
	}
	resp, err := grequests.Post(fmt.Sprintf(ConfigUrl, common.GetRandomManageAddr()), rOption)
	if err != nil {
		ylog.Errorf("GetConfigFromRemote", "error %s %s", agentID, err.Error())
		return nil, err
	}
	if !resp.Ok {
		ylog.Errorf("GetConfigFromRemote", "response code is not 200, AgentID: %s, StatusCode: %d, String: %s", agentID, resp.StatusCode, resp.String())
		return nil, errors.New("status code is not ok")
	}

	var response ResAgentConf
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("GetConfigFromRemote", "agentID: %s, error: %s, resp: %s", agentID, err.Error(), resp.String())
		return nil, err
	}

	// 检查业务响应码是否为非 0
	if response.Code != 0 {
		// 如果 Code 不为 0，处理异常情况
		errMsg := fmt.Sprintf("response code is %d, message: %s", response.Code, response.Message)

		// 检查 data 字段的类型是否为字符串
		var errData string
		if err := json.Unmarshal(response.Data, &errData); err == nil {
			errMsg = fmt.Sprintf("%s, data: %s", errMsg, errData)
		}

		ylog.Errorf("GetConfigFromRemote", "agentID: %s, %s", agentID, errMsg)
		return nil, errors.New(errMsg)
	}

	// 如果 Code 为 0，则继续处理 data 作为配置数组
	var configData []ConfigMsg
	err = json.Unmarshal(response.Data, &configData)
	if err != nil {
		ylog.Errorf("GetConfigFromRemote", "agentID: %s, error: %s, resp: %s", agentID, err.Error(), resp.String())
		return nil, err
	}

	res := make([]*pb.ConfigItem, 0)
	for _, v := range configData {
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
		&grequests.RequestOptions{
			JSON:    map[string][]string{"id_list": idList},
			Headers: map[string]string{"token": GetToken()},
		},
	)
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
		JSON:    fp,
		Headers: map[string]string{"token": GetToken()},
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
		ylog.Debugf("CheckCommonConfig", "response code is not 0, agentID: %s, resp: %s", fp.AgentID, resp.String())

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
		JSON:    ri,
		Headers: map[string]string{"token": GetToken()},
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

type IaasInfoReq struct {
	AgentID []string `json:"agent_id"`
	Region  string   `json:"region"`
}

type IaasInfoResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		InstanceList []struct {
			AgentID   string `json:"agent_id"`
			AccountID string `json:"account_id"`
		} `json:"instance_list"`
		MissingIds []string `json:"missing_ids"`
	} `json:"data"`
}

func GetIaasInfoFromRemote(id string) (res string, err error) {
	req := IaasInfoReq{
		AgentID: []string{id},
	}
	resp, err := grequests.Post(fmt.Sprintf(IaasInfoUrl, common.GetRandomManageAddr()),
		&grequests.RequestOptions{
			Headers: map[string]string{"token": GetToken()},
			JSON:    req,
		})
	if err != nil {
		ylog.Errorf("GetIaasInfoFromRemote", "Post Error, %s", err.Error())
		return res, err
	}

	if !resp.Ok {
		ylog.Errorf("GetIaasInfoFromRemote", "response code is not 200 but %d", resp.StatusCode)
		return res, errors.New("status code is not ok")
	}
	var response IaasInfoResp
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("GetIaasInfoFromRemote", "Error, %s", resp.String())
		return res, err
	}
	if response.Code != 0 {
		ylog.Errorf("GetIaasInfoFromRemote", "response code is not 0, %s %s", resp.String())
		return res, errors.New("response code is not 0")
	}
	for _, v := range response.Data.InstanceList {
		if v.AgentID == id {
			return v.AccountID, nil
		}
	}
	return res, nil
}
