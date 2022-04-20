package client

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/levigross/grequests"
	"time"
)

const TaskUrl = `http://%s/api/v1/agent/updateSubTask`

type ResTaskConf struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

func PostTask(postList []map[string]string) {
	resp, err := grequests.Post(fmt.Sprintf(TaskUrl, getRandomManageAddr()), &grequests.RequestOptions{
		JSON:           postList,
		RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		ylog.Errorf("PostTask", "error: %s, %#v", err.Error(), postList)
		return
	}
	if !resp.Ok {
		ylog.Errorf("PostTask", "response code is %d, %#v", resp.StatusCode, postList)
		return
	}

	var response ResTaskConf
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		ylog.Errorf("PostTask", "error: %s, %s", err.Error(), resp.String())
		return
	}
	if response.Code != 0 {
		ylog.Errorf("GetConfigFromRemote", "response code is not 0, %s", resp.String())
		return
	}
}
