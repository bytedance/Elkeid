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

const VerifyInstallKeyUrl = `http://%s/api/v1/agent/verifyInstallKey`

type VerifyInstallResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		AccountID string `json:"account_id"`
	} `json:"data"`
}

// VerifyInstallKey sends a request to verify the install key and returns the success status and account ID
func VerifyInstallKey(body pb.VerifyInstallRequest) (bool, string, error) {
	ylog.Debugf("VerifyInstallKey", "Sending request with body: %#v", body)

	url := fmt.Sprintf(VerifyInstallKeyUrl, common.GetRandomManageAddr())
	options := &grequests.RequestOptions{
		JSON:           body,
		RequestTimeout: 10 * time.Second,
		Headers:        map[string]string{"token": GetToken()},
	}

	resp, err := grequests.Post(url, options)
	if err != nil {
		ylog.Errorf("VerifyInstallKey", "Request failed: %v, body: %#v", err, body)
		return false, "", err
	}

	if resp.StatusCode != 200 {
		ylog.Errorf("VerifyInstallKey", "Received non-200 response: %d, body: %#v", resp.StatusCode, body)
		return false, "", fmt.Errorf("response code is %d", resp.StatusCode)
	}

	var response VerifyInstallResponse
	if err := json.Unmarshal(resp.Bytes(), &response); err != nil {
		ylog.Errorf("VerifyInstallKey", "Failed to parse JSON response: %v, response: %s", err, resp.String())
		return false, "", err
	}

	if response.Code != 0 {
		ylog.Errorf("VerifyInstallKey", "Verification failed with code %d, message: %s, response: %s", response.Code, response.Msg, resp.String())
		return false, "", nil
	}

	ylog.Infof("VerifyInstallKey", "Verification succeeded for account ID: %s", response.Data.AccountID)
	return true, response.Data.AccountID, nil
}
