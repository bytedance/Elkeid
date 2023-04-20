package container

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"go.mongodb.org/mongo-driver/bson"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"strings"
)

// 获取k8s链接句柄
func GetKubeClientSet(kubeConfig string) (kubeClient *kubernetes.Clientset, err error) {
	if kubeConfig == "" {
		return nil, fmt.Errorf("kube_config can not be empty")
	}

	// 通过集群id获取集群kubeconfig
	//if clusterId != "" {
	//	var clusterConfig ClusterConfig
	//	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	//	kubeConfCol.FindOne(context.Background(), bson.M{"cluster_id":clusterId}).Decode(&clusterConfig)
	//	kubeConfig = clusterConfig.KubeConfig
	//}

	clientConfig, err := clientcmd.NewClientConfigFromBytes([]byte(kubeConfig))
	if err != nil {
		return
	}
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return
	}
	kubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return
	}
	_, err = kubeClient.ServerVersion()
	if err != nil {
		return
	}
	return
}

// 获取集群信息
func getClusterInfo(c context.Context, clientset *kubernetes.Clientset, clusterId string) (clusterInfo ClusterInfo, err error) {
	serverVersion, err := clientset.ServerVersion()
	if err == nil {
		clusterInfo.ClusterVersion = serverVersion.String()
	}
	// 关联告警信息
	alarmCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeAlarmCollectionV1)
	cursor, _ := alarmCol.Find(c, bson.M{"cluster_id": clusterId})
	for cursor.Next(c) {
		level, ok := cursor.Current.Lookup("level").StringValueOK()
		if ok {
			switch level {
			case "critical":
				clusterInfo.Risk.Alarm.Critical += 1
			case "high":
				clusterInfo.Risk.Alarm.High += 1
			case "medium":
				clusterInfo.Risk.Alarm.Medium += 1
			case "low":
				clusterInfo.Risk.Alarm.Low += 1
			}
			clusterInfo.Risk.Alarm.Total += 1
		}
	}

	// 关联事件信息
	eventCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeEventCollectionV1)
	cursor, _ = eventCol.Find(c, bson.M{"clusters.cluster_id": clusterId})
	for cursor.Next(c) {
		level, ok := cursor.Current.Lookup("level").StringValueOK()
		if ok {
			switch level {
			case "critical":
				clusterInfo.Risk.Event.Critical += 1
			case "high":
				clusterInfo.Risk.Event.High += 1
			case "medium":
				clusterInfo.Risk.Event.Medium += 1
			case "low":
				clusterInfo.Risk.Event.Low += 1
			}
			clusterInfo.Risk.Event.Total += 1
		}
	}

	// 关联威胁分析信息
	behaviorCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeAbnormalBehaviorCollectionV1)
	resourceCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeThreatResourceCreatV1)
	vulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeVulnExploitV1)

	count, err := behaviorCol.CountDocuments(c, bson.M{"cluster_id": clusterId})
	if err == nil {
		clusterInfo.Risk.Threat.ErrorBehavior += count
		clusterInfo.Risk.Threat.Total += count
	}
	count, err = resourceCol.CountDocuments(c, bson.M{"cluster_id": clusterId})
	if err == nil {
		clusterInfo.Risk.Threat.ThreatSourceCreate += count
		clusterInfo.Risk.Threat.Total += count
	}
	count, err = vulnCol.CountDocuments(c, bson.M{"cluster_id": clusterId})
	if err == nil {
		clusterInfo.Risk.Threat.VulnExploit += count
		clusterInfo.Risk.Threat.Total += count
	}

	// 获取组件状态信息
	var clusterConfig ClusterConfig
	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	err = clusterCol.FindOne(c, bson.M{"cluster_id": clusterId}).Decode(&clusterConfig)
	if err != nil {
		clusterInfo.ModuleStatus.Threat.Status = ClusterModuleInactive
		clusterInfo.ModuleStatus.Baseline.Status = ""
		clusterInfo.ModuleStatus.Application.Status = ""
		clusterInfo.ModuleStatus.Exposure.Status = ClusterModuleInactive
	} else {
		clusterInfo.ModuleStatus.Baseline.Status = clusterConfig.ModuleStatus.Baseline
		clusterInfo.ModuleStatus.Threat.Status = clusterConfig.ModuleStatus.Threat
		clusterInfo.ModuleStatus.Application.Status = clusterConfig.ModuleStatus.Application
		clusterInfo.ModuleStatus.Exposure.Status = clusterConfig.ModuleStatus.Exposure
		// 兼容旧版本
		if clusterInfo.ModuleStatus.Exposure.Status == "" {
			clusterInfo.ModuleStatus.Exposure.Status = ClusterModuleInactive
		}
	}
	return
}

// 获取节点信息
func getNodeListInfo(c context.Context, clientset *kubernetes.Clientset) (nodeList []ClusterNodeInfo, err error) {
	nodes, err := clientset.CoreV1().Nodes().List(c, metav1.ListOptions{})
	for _, node := range nodes.Items {
		var nodeInfo ClusterNodeInfo
		nodeInfo.NodeName = node.Name
		nodeInfo.NodeId = string(node.UID)
		nodeInfo.NodeVersion = node.Status.NodeInfo.KubeletVersion
		nodeInfo.KernelVersion = node.Status.NodeInfo.KernelVersion
		nodeInfo.Runtime = node.Status.NodeInfo.ContainerRuntimeVersion
		nodeInfo.SystemImage = node.Status.NodeInfo.OSImage

		// 获取节点角色
		for label := range node.Labels {
			pos := strings.Index(label, "node-role.kubernetes.io/")
			if pos == 0 {
				// get the role
				tmpA := strings.Split(label, "/")
				if len(tmpA) != 2 {
					continue
				}
				if len(tmpA[1]) > 0 {
					if nodeInfo.NodeRole != "" {
						nodeInfo.NodeRole += ","
					}
					nodeInfo.NodeRole += tmpA[1]
				}
			}
		}
		// 获取节点网络信息
		for _, n := range node.Status.Addresses {
			switch n.Type {
			case corev1.NodeHostName:
				nodeInfo.HostName = n.Address
			case corev1.NodeExternalIP:
				nodeInfo.ExtranetIp = n.Address
			case corev1.NodeInternalIP:
				nodeInfo.IntranetIp = n.Address
			default:
				// do nothing
			}
		}
		// 获取节点系统信息
		for _, s := range node.Status.Conditions {
			if s.Type == corev1.NodeReady {
				switch s.Status {
				case corev1.ConditionTrue:
					nodeInfo.NodeStatus = "ready"
				case corev1.ConditionFalse:
					nodeInfo.NodeStatus = "not_ready"
				default:
					nodeInfo.NodeStatus = "unknown"
				}
			}
		}
		nodeList = append(nodeList, nodeInfo)
	}
	return
}

// 获取工作负载信息
func getWorkerListInfo(c context.Context, clientset *kubernetes.Clientset) (workerList []ClusterWorkerInfo, err error) {
	namespaceList, err := clientset.CoreV1().Namespaces().List(c, metav1.ListOptions{})
	if err != nil {
		return
	}
	for _, ns := range namespaceList.Items {
		if ns.Status.Phase != corev1.NamespaceActive {
			continue
		}
		workerMap := make(map[string]ClusterWorkerInfo, 0)
		workerDepend := make(map[string][]string, 0) // worker依赖关系
		// 获取工作负载信息
		daemonsets, err := clientset.AppsV1().DaemonSets(ns.Name).List(c, metav1.ListOptions{})

		if err == nil {
			for _, daemonset := range daemonsets.Items {
				workerInfo := ClusterWorkerInfo{
					WorkerId:   string(daemonset.UID),
					WorkerType: ClusterWorkerDaemonSet,
					WorkerName: daemonset.Name,
					Namespace:  ns.Name,
					CreateTime: daemonset.CreationTimestamp.Unix(),
				}
				workerMap[workerInfo.WorkerId] = workerInfo
			}
		}

		statefuls, err := clientset.AppsV1().StatefulSets(ns.Name).List(c, metav1.ListOptions{})
		if err == nil {
			for _, stateful := range statefuls.Items {
				workerInfo := ClusterWorkerInfo{
					WorkerId:   string(stateful.UID),
					WorkerType: ClusterWorkerStatefulSet,
					WorkerName: stateful.Name,
					Namespace:  ns.Name,
					CreateTime: stateful.CreationTimestamp.Unix(),
				}
				workerMap[workerInfo.WorkerId] = workerInfo
			}
		}

		deployments, err := clientset.AppsV1().Deployments(ns.Name).List(c, metav1.ListOptions{})
		if err == nil {
			for _, deployment := range deployments.Items {
				workerInfo := ClusterWorkerInfo{
					WorkerId:   string(deployment.UID),
					WorkerType: ClusterWorkerDeployment,
					WorkerName: deployment.Name,
					Namespace:  ns.Name,
					CreateTime: deployment.CreationTimestamp.Unix(),
				}
				workerMap[workerInfo.WorkerId] = workerInfo
			}
		}

		cronjobs, err := clientset.BatchV1().CronJobs(ns.Name).List(c, metav1.ListOptions{})
		if err == nil {
			for _, cronjob := range cronjobs.Items {
				workerInfo := ClusterWorkerInfo{
					WorkerId:   string(cronjob.UID),
					WorkerType: ClusterWorkerCronJob,
					WorkerName: cronjob.Name,
					Namespace:  ns.Name,
					CreateTime: cronjob.CreationTimestamp.Unix(),
				}
				workerMap[workerInfo.WorkerId] = workerInfo
			}
		}

		jobs, err := clientset.BatchV1().Jobs(ns.Name).List(c, metav1.ListOptions{})
		if err == nil {
			for _, job := range jobs.Items {
				// 判断job是否有上级
				jobId := string(job.UID)
				if len(job.OwnerReferences) == 0 {
					workerInfo := ClusterWorkerInfo{
						WorkerId:   jobId,
						WorkerType: ClusterWorkerJob,
						WorkerName: job.Name,
						Namespace:  ns.Name,
						CreateTime: job.CreationTimestamp.Unix(),
					}
					workerMap[workerInfo.WorkerId] = workerInfo
				} else {
					for _, owner := range job.OwnerReferences {
						workerDepend[jobId] = append(workerDepend[jobId], string(owner.UID))
					}
				}
			}
		}

		replicasets, err := clientset.AppsV1().ReplicaSets(ns.Name).List(c, metav1.ListOptions{})
		if err == nil {
			for _, replicaset := range replicasets.Items {
				// 判断job是否有上级
				replicasetId := string(replicaset.UID)
				if len(replicaset.OwnerReferences) == 0 {
					workerInfo := ClusterWorkerInfo{
						WorkerId:   replicasetId,
						WorkerType: ClusterWorkerReplicaSet,
						WorkerName: replicaset.Name,
						Namespace:  ns.Name,
						CreateTime: replicaset.CreationTimestamp.Unix(),
					}
					workerMap[workerInfo.WorkerId] = workerInfo
				} else {
					for _, owner := range replicaset.OwnerReferences {
						workerDepend[replicasetId] = append(workerDepend[replicasetId], string(owner.UID))
					}
				}
			}
		}

		// 关联工作负载和pod信息
		pods, err := clientset.CoreV1().Pods(ns.Name).List(c, metav1.ListOptions{})
		for _, pod := range pods.Items {
			for _, owner := range pod.OwnerReferences {
				ownerId := string(owner.UID)
				if _, ok := workerDepend[ownerId]; !ok {
					if _, ok := workerMap[ownerId]; ok {
						workerInfo := workerMap[ownerId]
						workerInfo.PodList = append(workerInfo.PodList, pod.Name)
						workerMap[ownerId] = workerInfo
					}
				} else {
					for _, ownerId = range workerDepend[ownerId] {
						if _, ok := workerMap[ownerId]; ok {
							workerInfo := workerMap[ownerId]
							workerInfo.PodList = append(workerInfo.PodList, pod.Name)
							workerMap[ownerId] = workerInfo
						}
					}
				}
			}
		}

		// 返回工作负载列表
		for _, workerInfo := range workerMap {
			if len(workerInfo.PodList) != 0 {
				workerList = append(workerList, workerInfo)
			}
		}
	}
	return
}

// 获取pod信息
func getPodListInfo(c context.Context, clientset *kubernetes.Clientset) (podList []ClusterPodInfo, containerList []ClusterContainerInfo, err error) {
	pods, err := clientset.CoreV1().Pods("").List(c, metav1.ListOptions{})
	for _, pod := range pods.Items {
		podInfo := ClusterPodInfo{
			PodName:    pod.Name,
			PodId:      string(pod.UID),
			Namespace:  pod.Namespace,
			PodStatus:  string(pod.Status.Phase),
			PodIp:      pod.Status.PodIP,
			NodeIp:     pod.Status.HostIP,
			NodeName:   pod.Spec.NodeName,
			CreateTime: pod.CreationTimestamp.Unix(),
		}
		for _, container := range pod.Status.ContainerStatuses {
			containerInfo := ClusterContainerInfo{
				ContainerId:   container.ContainerID,
				ContainerName: container.Name,
				Image:         container.Image,
				PodId:         string(pod.UID),
			}
			containerList = append(containerList, containerInfo)
		}
		podList = append(podList, podInfo)
	}
	return
}
