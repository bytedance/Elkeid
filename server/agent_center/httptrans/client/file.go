package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/levigross/grequests"
)

const (
	DownLoadFileUrl = `http://%s/api/v6/investigate/file/DownloadFileByToken`
	UploadFileUrl   = "http://%s/api/v6/shared/Upload"
)

type UploadResp struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
	Data    string `json:"data"`
}

func UploadFile(filePath string, hash string) (string, error) {
	fd, err := grequests.FileUploadFromDisk(filePath)
	if err != nil {
		return "", err
	}
	resp, err := grequests.Post(fmt.Sprintf(UploadFileUrl, common.GetRandomManageAddr()),
		&grequests.RequestOptions{
			Files: fd,
			Data:  map[string]string{"hash": hash},
		})
	if err != nil {
		return "", err
	}
	if !resp.Ok {
		ylog.Errorf("UploadFile", "UploadFile error %s", resp.String())
		return "", errors.New("status code is not 200")
	}

	rsp := UploadResp{}
	err = json.Unmarshal(resp.Bytes(), &rsp)
	if err != nil {
		return "", err
	}
	if rsp.Code == 0 {
		return rsp.Data, nil
	} else {
		ylog.Errorf("UploadFile", "UploadFile error %s", resp.String())
		return "", errors.New(resp.String())
	}
}

func GetFileFromRemote(token string) ([]byte, error) {
	resp, err := grequests.Post(
		fmt.Sprintf(DownLoadFileUrl, common.GetRandomManageAddr()),
		&grequests.RequestOptions{JSON: map[string]interface{}{"token": token}})
	if err != nil {
		ylog.Errorf("GetFileFromRemote", "Post Error, %s", err.Error())
		return nil, err
	}

	if !resp.Ok {
		ylog.Errorf("GetFileFromRemote", "response code is not 200 but %d", resp.StatusCode)
		return nil, fmt.Errorf("status code is %d", resp.StatusCode)
	}
	return resp.Bytes(), nil
}
