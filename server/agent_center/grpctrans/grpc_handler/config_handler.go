package grpc_handler

import (
	"context"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"strings"
	"sync"
	"time"
)

const refreshInterval = 30 * time.Minute

var GlobalConfigHandler *ConfigExtHandler

type ConfigExtHandler struct {
	cache map[string]*FingerPrint //agent_id+plugins:FingerPrint
	lock  sync.RWMutex
}

type FingerPrint struct {
	AgentID    string
	PluginName string
	SecretKey  string
	Release    string
	Version    string
	Items      map[string]*pb.ConfigFingerPrint //path:ConfigFingerPrint
}

func (c *ConfigExtHandler) Init() {
	c.cache = make(map[string]*FingerPrint, 0)
	go c.autoRefreshRelease()
}

func (c *ConfigExtHandler) SetGlobal() {
	GlobalConfigHandler = c
}

func (c *ConfigExtHandler) autoRefreshRelease() {
	tk := time.NewTicker(refreshInterval)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			//全量请求后端，校验release版本号
			releases := make([]*common.ConfigReleaseInfo, 0)

			c.lock.RLock()
			for _, fp := range c.cache {
				releases = append(releases, &common.ConfigReleaseInfo{
					AgentID: fp.AgentID,
					Plugin:  fp.PluginName,
					Status:  0, //用不到
					Release: fp.Release,
				})
			}
			c.lock.RUnlock()

			releasesRemote, err := client.VerifyCommonConfigRelease(releases)
			if err != nil {
				ylog.Errorf("autoRefresh", "VerifyCommonConfigRelease error %s", err.Error())
			}
			c.VerifyAndUpdateRelease(releasesRemote)
		}
	}
}

func (c *ConfigExtHandler) VerifyAndUpdateRelease(ri []*common.ConfigReleaseInfo) {
	for _, fp := range ri {
		localFP := c.GetFingerPrint(fp.AgentID, fp.Plugin)
		if localFP == nil || fp.Release != localFP.Release {

			//校验release号失败，请求远端获取详情
			freshRequest := &pb.ConfigRefreshRequest{
				AgentID:     fp.AgentID,
				PluginName:  fp.Plugin,
				Fingerprint: make([]*pb.ConfigFingerPrint, 0),
			}
			if localFP != nil {
				for k, _ := range localFP.Items {
					freshRequest.Fingerprint = append(freshRequest.Fingerprint, localFP.Items[k])
				}
			}
			freshResponse, err := client.CheckCommonConfig(freshRequest)
			if err != nil {
				ylog.Errorf("VerifyAndUpdateRelease", "CheckCommonConfig error %s", err.Error())
				continue
			}

			//将结果刷新到本地缓存
			c.writeCache(freshResponse)
		}
	}
}

func (c *ConfigExtHandler) GetFingerPrint(agentID, plugin string) *FingerPrint {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if cache, ok := c.cache[agentID+plugin]; ok {
		return cache
	}
	return nil
}

func (c *ConfigExtHandler) Delete(agentID string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k, v := range c.cache {
		if strings.HasPrefix(k, agentID) {
			delete(c.cache, k)
			ylog.Infof("ConfigExtHandler_Delete", "Delete %s, %s", v.AgentID, v.PluginName)
		}
	}
}

func (c *ConfigExtHandler) writeCache(cr *common.ConfigRefreshResponse) {
	tmp := &FingerPrint{
		AgentID:    cr.AgentID,
		PluginName: cr.PluginName,
		SecretKey:  cr.SecretKey,
		Release:    cr.Release,
		Version:    cr.Version,
		Items:      nil,
	}
	for _, v := range cr.Config {
		tmp.Items[v.Path] = &pb.ConfigFingerPrint{
			Path:   v.Path,
			Hash:   v.Hash,
			Status: pb.ConfigFingerPrint_StatusCode(v.Status),
		}
	}

	c.lock.Lock()
	c.cache[cr.AgentID+cr.PluginName] = tmp
	c.lock.Unlock()
}

func (c *ConfigExtHandler) CheckConfig(ctx context.Context, request *pb.ConfigRefreshRequest) (*pb.ConfigRefreshResponse, error) {
	localFP := c.GetFingerPrint(request.AgentID, request.PluginName)
	checkSuccess := true
	if localFP != nil {
		for _, v := range request.GetFingerprint() {
			item, ok := localFP.Items[v.Path]
			if ok && item.Hash == v.Hash && item.Status == v.Status {
				continue
			}
			//插件配置与localCache不匹配，去远端校验
			checkSuccess = false
			break
		}
	} else {
		checkSuccess = false
	}

	res := &pb.ConfigRefreshResponse{
		PluginName: request.PluginName,
		Status:     pb.ConfigRefreshResponse_SUCCESS,
		Config:     make([]*pb.ConfigDetail, 0),
	}

	//本地校验成功
	if checkSuccess {
		res.SecretKey = localFP.SecretKey
		res.Version = localFP.Version
		res.Release = localFP.Release
		return res, nil
	}

	//插件配置与localCache不匹配，去远端校验
	freshRequest := &pb.ConfigRefreshRequest{
		AgentID:     request.AgentID,
		PluginName:  request.PluginName,
		Fingerprint: make([]*pb.ConfigFingerPrint, 0),
	}
	if localFP != nil {
		for k, _ := range localFP.Items {
			freshRequest.Fingerprint = append(freshRequest.Fingerprint, localFP.Items[k])
		}
	}
	freshResponse, err := client.CheckCommonConfig(freshRequest)
	if err != nil {
		ylog.Errorf("CheckConfig", "CheckCommonConfig error %s", err.Error())
		return nil, err
	}

	//将结果刷新到本地缓存
	c.writeCache(freshResponse)
	for _, v := range freshResponse.Config {
		res.Config = append(res.Config, &pb.ConfigDetail{
			Path:   v.Path,
			Status: v.Status,
			Data:   v.Data,
			Type:   v.Type,
			Hash:   v.Hash,
			Detail: v.Detail,
		})

	}
	return res, nil
}
