package outputer

import (
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"math/rand"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/levigross/grequests"
)

type WorkSpace struct {
	NameSpace   string            `bson:"NameSpace"`
	ClusterName string            `bson:"ClusterName"`
	CreateAt    int64             `bson:"CreateAt"`
	Users       map[string]string `bson:"Users"`
}
type TestPluginReq struct {
	HubAddress string            `json:"hub_address"`
	PluginType string            `json:"plugin_type"`
	PluginName string            `json:"plugin_name"`
	Config     map[string]string `json:"config"`
	Data       interface{}       `json:"data"`
	Sha256Sum  string            `json:"sha256sum"`
}
type PluginInfo struct {
	// 不可修改，字段同时存在于zip包内
	// plugin type+name 组成唯一标识
	PluginName string `json:"plugin_name" bson:"plugin_name"`
	PluginType string `json:"plugin_type" bson:"plugin_type"`

	Description string `json:"description" bson:"description"`
	Runtime     string `json:"runtime" bson:"runtime"`
	Author      string `json:"author" bson:"author"`

	Sha256Sum string    `json:"sha256sum" bson:"sha256sum"`
	UploadAt  time.Time `json:"upload_at" bson:"upload_at"`
}
type HubTestPluginReq struct {
	PluginType string            `json:"plugin_type"`
	PluginName string            `json:"plugin_name"`
	Config     map[string]string `json:"config"`
	Data       interface{}       `json:"data"`
	Sha256Sum  string            `json:"sha256sum"`
	ZipBytes   []byte            `json:"zipBytes"`
}
type HubResponse struct {
	Success  bool        `json:"success"`
	Data     interface{} `json:"data"`
	ErrorMsg string      `json:"errormsg"`
}

func getHubList() ([]string, error) {
	if monitor.Config.HUB.SSHHost.Host == "" {
		return nil, errors.New("no hub address")
	}
	return []string{monitor.Config.HUB.SSHHost.Host}, nil
}
func ApplyHubPlugin(req TestPluginReq) (interface{}, error) {
	data, err := getHubList()
	if err != nil {
		ylog.Errorf("ApplyHubPlugin", "error: %s", err.Error())
		return nil, err
	}
	if len(data) <= 0 {
		return nil, errors.New("no hub list for ApplyHubPlugin")
	}
	hubAddress := data[rand.Int31n(int32(len(data)))]
	pluginInfo := &PluginInfo{
		PluginName: req.PluginName,
		PluginType: req.PluginType,
	}
	testUrl := fmt.Sprintf("%s://%s:8091%s", "https", hubAddress, "/testPlugin")
	option := midware.HubAuthRequestOption()
	option.DialTimeout = time.Second * 5
	option.RequestTimeout = time.Second * 30
	option.JSON = HubTestPluginReq{
		PluginType: pluginInfo.PluginType,
		PluginName: pluginInfo.PluginName,
		Config:     req.Config,
		Data:       req.Data,
	}
	resp, err := grequests.Post(testUrl, option)
	if err != nil {
		ylog.Errorf("ApplyHubPlugin", "test python plugin to hub err: %s", err.Error())
		return nil, err
	} else {
		var testResp HubResponse
		err = resp.JSON(&testResp)
		// ylog.Infof("ApplyHubPlugin ", "url %s request %+v object %+v", testUrl, option, resp.StatusCode, testResp)
		// ylog.Infof("ApplyHubPlugin post", "url %s request object %+v", testUrl, option.JSON)
		// ylog.Infof("ApplyHubPlugin post", "url %s response object %+v", testUrl, testResp)
		if err != nil {
			ylog.Errorf("ApplyHubPlugin", "test python plugin resp bind err: %s", err.Error())
			return nil, err
		} else {
			if testResp.Success {
				return testResp.Data, nil
			} else {
				ylog.Errorf("ApplyHubPlugin", "test python plugin err: %s", testResp.ErrorMsg)
				return nil, fmt.Errorf(testResp.ErrorMsg)
			}
		}
	}
}
