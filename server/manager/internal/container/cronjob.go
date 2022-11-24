package container

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

// 生成k8s数据
const KubeClusterSyncLock = "KubeClusterSyncLock"

func SetKubeData(setType string) {

	c := context.Background()
	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	kubeClusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	kubeNodeCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeNodeInfo)
	kubeWorkerCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeWorkerInfo)
	kubePodCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubePodInfo)
	kubeContainerCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeContainerInfo)

	setData := func() {
		writeOption := &options.BulkWriteOptions{}
		writeOption.SetOrdered(false)
		var kubeClusterWrites []mongo.WriteModel
		var kubeNodeWrites []mongo.WriteModel
		var kubeWorkerWrites []mongo.WriteModel
		var kubePodWrites []mongo.WriteModel
		var kubeContainerWrites []mongo.WriteModel
		clusterConfigCur, _ := kubeConfCol.Find(c, bson.M{})
		updateTime := time.Now().Unix()
		for clusterConfigCur.Next(c) {
			// 获取k8s句柄
			var clusterConfig ClusterConfig
			err := clusterConfigCur.Decode(&clusterConfig)
			clusterId := clusterConfig.ClusterId
			clientset, err := GetKubeClientSet(clusterConfig.KubeConfig)

			if err != nil {
				kubeConfBson := bson.M{}
				if clusterConfig.ClusterStatus == ClusterStatusRunning {
					kubeConfBson["cluster_status"] = ClusterStatusError
					_, err = kubeClusterCol.UpdateOne(c, bson.M{"cluster_id": clusterConfig.ClusterId}, bson.M{"$set": bson.M{"cluster_status": ClusterStatusError}})
				}
				kubeConfBson["err_reason"] = err.Error()
				_, err = kubeConfCol.UpdateOne(c, bson.M{"cluster_id": clusterConfig.ClusterId}, bson.M{"$set": kubeConfBson})
				continue
			} else {
				if clusterConfig.ClusterStatus == ClusterStatusError {
					_, err = kubeConfCol.UpdateOne(c, bson.M{"cluster_id": clusterConfig.ClusterId}, bson.M{"$set": bson.M{"cluster_status": ClusterStatusRunning}})
					_, err = kubeClusterCol.UpdateOne(c, bson.M{"cluster_id": clusterConfig.ClusterId}, bson.M{"$set": bson.M{"cluster_status": ClusterStatusRunning}})
					clusterConfig.ErrReason = ""
				}
			}

			// 容器集群数据生成
			var clusterInfo ClusterInfo
			clusterInfo, err = getClusterInfo(c, clientset, clusterId)
			clusterInfo.ClusterId = clusterId
			clusterInfo.ClusterName = clusterConfig.ClusterName
			clusterInfo.ClusterRegion = clusterConfig.ClusterRegion
			clusterInfo.CreateTime = clusterConfig.CreateTime
			clusterInfo.UpdateTime = updateTime

			// 节点信息生成
			nodeList, _ := getNodeListInfo(c, clientset)
			clusterInfo.NodeNum = int64(len(nodeList))
			for _, nodeInfo := range nodeList {
				nodeInfo.ClusterId = clusterId
				nodeInfo.ClusterName = clusterInfo.ClusterName
				nodeInfo.ClusterRegion = clusterInfo.ClusterRegion
				nodeInfo.UpdateTime = updateTime
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"node_id": nodeInfo.NodeId}).
					SetUpdate(bson.M{"$set": nodeInfo}).SetUpsert(true)
				kubeNodeWrites = append(kubeNodeWrites, model)
			}

			// 工作负载信息生成
			workerList, _ := getWorkerListInfo(c, clientset)
			clusterInfo.WorkerNum = int64(len(workerList))
			for _, workerInfo := range workerList {
				workerInfo.ClusterId = clusterId
				workerInfo.UpdateTime = updateTime
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"worker_id": workerInfo.WorkerId}).
					SetUpdate(bson.M{"$set": workerInfo}).SetUpsert(true)
				kubeWorkerWrites = append(kubeWorkerWrites, model)
			}

			// pod,容器信息生成
			podList, containerList, _ := getPodListInfo(c, clientset)
			clusterInfo.PodNum = int64(len(podList))
			for _, podInfo := range podList {
				podInfo.ClusterId = clusterId
				podInfo.UpdateTime = updateTime
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"pod_id": podInfo.PodId}).
					SetUpdate(bson.M{"$set": podInfo}).SetUpsert(true)
				kubePodWrites = append(kubePodWrites, model)
			}

			for _, containerInfo := range containerList {
				containerInfo.ClusterId = clusterId
				containerInfo.UpdateTime = updateTime
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"container_id": containerInfo.ContainerId}).
					SetUpdate(bson.M{"$set": containerInfo}).SetUpsert(true)
				kubeContainerWrites = append(kubeContainerWrites, model)
			}

			// 存储容器集群数据
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"cluster_id": clusterInfo.ClusterId}).
				SetUpdate(bson.M{"$set": clusterInfo}).SetUpsert(true)
			kubeClusterWrites = append(kubeClusterWrites, model)
		}
		// 插入新数据
		_, err := kubeClusterCol.BulkWrite(c, kubeClusterWrites, writeOption)
		_, err = kubeNodeCol.BulkWrite(c, kubeNodeWrites, writeOption)
		_, err = kubeWorkerCol.BulkWrite(c, kubeWorkerWrites, writeOption)
		_, err = kubePodCol.BulkWrite(c, kubePodWrites, writeOption)
		_, err = kubeContainerCol.BulkWrite(c, kubeContainerWrites, writeOption)

		// 清空历史数据
		_, err = kubeClusterCol.DeleteMany(c, bson.M{"update_time": bson.M{"$ne": updateTime}})
		_, err = kubeNodeCol.DeleteMany(c, bson.M{"update_time": bson.M{"$ne": updateTime}})
		_, err = kubeWorkerCol.DeleteMany(c, bson.M{"update_time": bson.M{"$ne": updateTime}})
		_, err = kubePodCol.DeleteMany(c, bson.M{"update_time": bson.M{"$ne": updateTime}})
		_, err = kubeContainerCol.DeleteMany(c, bson.M{"update_time": bson.M{"$ne": updateTime}})
		if err != nil {
			return
		}
	}

	switch setType {
	case "crontab":
		timer := time.NewTicker(time.Minute * time.Duration(5))
		for {
			select {
			case <-timer.C:
				lockSuccess, err := infra.Grds.SetNX(context.Background(), KubeClusterSyncLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					setData()
					_, err := infra.Grds.Del(context.Background(), KubeClusterSyncLock).Result()
					if err != nil {
						return
					}
				}
			}
		}
	case "once":
		lockSuccess, err := infra.Grds.SetNX(context.Background(), KubeClusterSyncLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			setData()
			_, err := infra.Grds.Del(context.Background(), KubeClusterSyncLock).Result()
			if err != nil {
				return
			}
		}
	}
}
