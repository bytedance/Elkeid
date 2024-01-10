package cluster

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/common"
	"github.com/bytedance/Elkeid/server/service_discovery/common/safemap"
	"github.com/bytedance/Elkeid/server/service_discovery/common/ylog"
	"strconv"

	"time"
)

const (
	defaultMemberExpireTime    = 90
	defaultMemberFreshInterval = 10
)

var (
	memberKey   = fmt.Sprintf("MEMBER:%s:", common.Clusterkey)
	clusterName = fmt.Sprintf("ServiceDiscovery_%s", common.Clusterkey)
	clusterKey  = fmt.Sprintf("CLUSTER_%s", common.Clusterkey)
)

type ConfigCluster struct {
	BaseCluster
}

func NewConfigCluster(host string, mode string) Cluster {
	cc := &ConfigCluster{BaseCluster{
		Mode:    mode,
		Host:    host,
		Members: safemap.NewSafeMap(clusterName),
		Done:    make(chan bool),
	}}

	if mode == common.RunModeRedis {
		cc.registry()
		go cc.redisRefresh()
	} else {
		go cc.refresh()
	}
	go cc.ping()

	return cc
}

func (cc *ConfigCluster) registry() {
	ylog.Infof("ConfigCluster", "registry!")
	//create ts
	ts := time.Now().Unix()
	//set redis and mem
	common.Grds.HSet(context.Background(), clusterKey, cc.Host, ts)
	cc.Members.HSet(clusterName, cc.Host, ts)
	member := fmt.Sprintf(memberKey, cc.Host)
	common.Grds.Set(context.Background(), member, ts, defaultMemberExpireTime*time.Second)
	//sync mem
	rdsMembers := common.Grds.HGetAll(context.Background(), clusterKey).Val()
	for host, item := range rdsMembers {
		member = fmt.Sprintf(memberKey, host)
		if common.Grds.Exists(context.Background(), member).Val() == 0 {
			continue
		}
		ts, _ = strconv.ParseInt(item, 10, 64)
		cc.Members.HSet(clusterName, host, ts)
	}
	ylog.Infof("ConfigCluster", "registry end!")
}

func (cc *ConfigCluster) redisRefresh() {
	var (
		member string
	)
	t := time.NewTicker(defaultMemberFreshInterval * time.Second)
	defer t.Stop()
	for {
		//endpoint内存缓存同步
		select {
		case <-t.C:
			//update
			ts := time.Now().Unix()
			//set redis and mem
			common.Grds.HSet(context.Background(), clusterKey, cc.Host, ts)
			cc.Members.HSet(clusterName, cc.Host, ts)
			member = fmt.Sprintf(memberKey, cc.Host)
			common.Grds.Set(context.Background(), member, ts, defaultMemberExpireTime*time.Second)
			//refresh redis
			rdsMembers := common.Grds.HGetAll(context.Background(), clusterKey).Val()
			for host, _ := range rdsMembers {
				member = fmt.Sprintf(memberKey, host)
				if common.Grds.Exists(context.Background(), member).Val() == 0 {
					//del redis
					common.Grds.HDel(context.Background(), clusterKey, host)
				} else {
					//set mem
					cc.Members.HSet(clusterName, host, ts)
				}
			}
			//clean mem
			memMembers := cc.Members.HKeys(clusterName)
			for _, host := range memMembers {
				member = fmt.Sprintf(memberKey, host)
				if common.Grds.Exists(context.Background(), member).Val() == 0 {
					//del mem
					cc.Members.HDel(clusterName, host)
				}
			}
		case <-cc.Done:
			ylog.Debugf("refresh", "cluster refesh strop\n")
			return
		}
	}
}

func (cc *ConfigCluster) refresh() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case changed := <-common.ConfigChangeNotify:
			if changed {
				members := common.V.GetStringSlice("Cluster.Members")
				cc.Members.Del(clusterName)
				for _, host := range members {
					cc.Members.HSet(clusterName, host, "ok")
				}
			}
		case <-t.C:
		case <-cc.Done:
			ylog.Debugf("refresh", "cluster refesh strop\n")
			return
		}
	}
}
