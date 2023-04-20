package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/levigross/grequests"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func InitClusterStatus() {
	interval := 60
	t := time.NewTicker(time.Duration(interval) * time.Second)
	defer t.Stop()
	for range t.C {
		lock := fmt.Sprintf("KUBE_CLUSTER_STATUS_LOCK:%d", time.Now().Unix()/int64(interval))
		ok := infra.Grds.SetNX(context.Background(), lock, 1, time.Duration(interval-1)*time.Second).Val()
		ylog.Infof("cluster_status_update", "setnx lock %s %v", lock, ok)
		if !ok {
			continue
		}
		err := updateKubeStatus()
		if err != nil {
			return
		}
	}
}

const (
	statusActive   = "active"
	statusInActive = "inactive"
)

func updateKubeStatus() error {
	remoteArr, err := getActiveCluster()
	if err != nil {
		ylog.Errorf("updateKubeStatus", "getActiveCluste error:%s", err.Error())
		return err
	}
	ylog.Infof("updateKubeStatus", "getActiveCluste %#v", remoteArr)

	kubeConfig := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)

	writes := make([]mongo.WriteModel, 0, 0)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for _, cID := range remoteArr {
		filter := bson.M{"cluster_id": cID}
		updates := bson.M{"$set": bson.M{"module_status.threat": statusActive}}
		model := mongo.NewUpdateOneModel().SetFilter(filter).SetUpdate(updates).SetUpsert(false)
		ylog.Infof("updateKubeStatus", "filter %#v,updates %#v", filter, updates)
		writes = append(writes, model)
	}
	if len(writes) > 0 {
		res, err := kubeConfig.BulkWrite(context.Background(), writes, writeOption)
		if err != nil {
			ylog.Errorf("updateKubeStatus", "kubeConfig BulkWrite error:%s len:%d", err.Error(), len(writes))
		} else {
			ylog.Debugf("updateKubeStatus", "kubeConfig MatchedCount:%d InsertedCount:%d ModifiedCount:%d ", res.MatchedCount, res.InsertedCount, res.ModifiedCount)
		}
	}

	updateRes, err := kubeConfig.UpdateMany(context.Background(), bson.M{"cluster_id": bson.M{"$nin": remoteArr}},
		bson.M{"$set": bson.M{"module_status.threat": statusInActive}})
	if err != nil {
		ylog.Errorf("updateKubeStatus", "kubeConfig UpdateMany error:%s len:%d", err.Error(), len(writes))
	} else {
		ylog.Debugf("updateKubeStatus", "kubeConfig UpsertedCount:%d MatchedCount:%d ModifiedCount:%d ", updateRes.UpsertedCount, updateRes.MatchedCount, updateRes.ModifiedCount)
	}
	return nil
}

type ClusterRsp struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data []string `json:"data"`
}

func getActiveCluster() ([]string, error) {
	hosts, err := discovery.FetchRegistryWithPort(fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName))
	if err != nil {
		return nil, err
	}

	arr := make([]string, 0, 0)
	for _, host := range hosts {
		url := fmt.Sprintf("https://%s/kube/cluster/list", host)
		option := midware.SvrAuthRequestOption()
		option.RequestTimeout = 5 * time.Second
		r, err := grequests.Get(url, option)
		if err != nil {
			ylog.Errorf("getActiveCluster", "Get error %s, %s", url, err.Error())
			continue
		}
		ylog.Debugf("getActiveCluster", " %s", r.String())

		rsp := ClusterRsp{}
		err = json.Unmarshal(r.Bytes(), &rsp)
		if err != nil {
			ylog.Errorf("getActiveCluster", "Get error %s, %s %s", url, err.Error(), r.String())
			continue
		}
		arr = infra.Union(arr, rsp.Data)
	}
	return arr, nil
}
