package client

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/levigross/grequests"
	"math/rand"
	"sync"
	"time"
)

const loginUrl = `http://%s/api/v1/user/login`

var (
	tokenMutex sync.RWMutex
	token      = ""
)

type tokenResp struct {
	Code int    `json:"code" bson:"code"`
	Msg  string `json:"msg" bson:"msg"`
	Data struct {
		Token string `json:"token" bson:"token"`
	} `json:"data" bson:"data"`
}

func init() {
	// 自动更新token
	for {
		err := updateToken()
		if err == nil {
			break
		}
		ylog.Errorf("[tokenRefresh]", "UpdateToken Error %s, retry after 2 second!", err.Error())
		time.Sleep(5 * time.Second)
	}

	go func() {
		for range time.Tick(time.Minute * 60) {
			// 自动更新token
			for {
				time.Sleep(time.Duration(rand.Intn(5)) * time.Second)
				err := updateToken()
				if err == nil {
					break
				}
				ylog.Errorf("[tokenRefresh]", "UpdateToken Error %s, retry after 10 second!", err.Error())
				time.Sleep(10 * time.Second)
			}
		}
	}()
}

func updateToken() error {
	url := fmt.Sprintf(loginUrl, common.GetRandomManageAddr())
	resp, err := grequests.Post(url, &grequests.RequestOptions{
		RequestTimeout: 10 * time.Second,
		JSON:           map[string]string{"username": common.UserName, "password": common.Password},
		Headers:        map[string]string{"Content-Type": "application/json"},
	})
	if err != nil {
		ylog.Errorf("[tokenRefresh]", "http post error: "+err.Error())
		return fmt.Errorf("http post error: %w", err)
	}
	tResp := tokenResp{}
	err = json.Unmarshal(resp.Bytes(), &tResp)
	if err != nil {
		ylog.Errorf("[tokenRefresh]", fmt.Sprintf(`result:%s error:%s url:%s`, resp.String(), err.Error(), url))
		return fmt.Errorf(`result:%s error:%w url:%s`, resp.String(), err, url)
	}
	if tResp.Code != 0 {
		ylog.Errorf("[tokenRefresh]", "resp code!=0 resp: "+resp.String())
		return fmt.Errorf("resp code!=0 resp: " + resp.String())
	}
	tokenMutex.Lock()
	token = tResp.Data.Token
	tokenMutex.Unlock()
	ylog.Infof("[tokenRefresh]", "success")
	return nil
}

func GetToken() string {
	tokenMutex.RLock()
	defer tokenMutex.RUnlock()
	return token
}
