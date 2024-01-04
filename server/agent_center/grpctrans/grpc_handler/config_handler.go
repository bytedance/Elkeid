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
	Release    uint64
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
		Items:      map[string]*pb.ConfigFingerPrint{},
	}
	for _, v := range cr.Config {
		//跳过无关文件
		if v.Type != pb.ConfigTypeCode_Remove && v.Data == "" && v.Hash == "" {
			continue
		}

		status := pb.ConfigFPStatusCode_Exist
		if v.Type == pb.ConfigTypeCode_Remove {
			status = pb.ConfigFPStatusCode_Nonexistent
		}
		tmp.Items[v.Path] = &pb.ConfigFingerPrint{
			Path:   v.Path,
			Hash:   v.Hash,
			Status: status,
		}
	}

	c.lock.Lock()
	c.cache[cr.AgentID+cr.PluginName] = tmp
	c.lock.Unlock()
}

func (c *ConfigExtHandler) CheckConfig(ctx context.Context, request *pb.ConfigRefreshRequest) (*pb.ConfigRefreshResponse, error) {
	localFP := c.GetFingerPrint(request.AgentID, request.PluginName)
	checkSuccess := true
	hitCount := 0

	if localFP != nil {
		for _, v := range request.GetFingerprint() {
			item, ok := localFP.Items[v.Path]
			if ok && item.Hash == v.Hash && item.Status == v.Status {
				//命中
				hitCount++
			}
		}

		if hitCount < len(localFP.Items) {
			checkSuccess = false
		}
	} else {
		checkSuccess = false
	}

	res := &pb.ConfigRefreshResponse{
		PluginName: request.PluginName,
		Status:     pb.ConfigStatusCode_SUCCESS,
		Config:     make([]*pb.ConfigDetail, 0),
	}

	//本地校验成功
	if checkSuccess {
		res.SecretKey = localFP.SecretKey
		res.Version = localFP.Version
		res.Release = localFP.Release
		ylog.Infof("CheckConfig_handler", "local check ok,request %s, response %s", request.String(), res.String())
		return res, nil
	}

	//插件配置与localCache不匹配，去远端校验
	freshRequest := &pb.ConfigRefreshRequest{
		AgentID:     request.AgentID,
		PluginName:  request.PluginName,
		Fingerprint: request.GetFingerprint(),
	}
	freshResponse, err := client.CheckCommonConfig(freshRequest)
	if err != nil {
		ylog.Infof("CheckConfig_handler", "local check failed, remote check failed, request %s, response %s, error %s", request.String(), res.String(), err.Error())
		return res, nil
	}

	//将结果刷新到本地缓存
	c.writeCache(freshResponse)

	//将结果封装返回远端
	status := pb.ConfigStatusCode_SUCCESS
	for _, v := range freshResponse.Config {
		//跳过无关文件
		if v.Type != pb.ConfigTypeCode_Remove && v.Data == "" && v.Hash == "" {
			continue
		}

		if v.Status == pb.ConfigStatusCode_FAILED {
			status = pb.ConfigStatusCode_FAILED
		}
		res.Config = append(res.Config, &pb.ConfigDetail{
			Path:   v.Path,
			Status: v.Status,
			Data:   v.Data,
			Type:   v.Type,
			Hash:   v.Hash,
			Detail: v.Detail,
		})

	}
	res.Status = status
	ylog.Infof("CheckConfig_handler", "remote check, request %s, response %s", request.String(), res.String())
	return res, nil
}
