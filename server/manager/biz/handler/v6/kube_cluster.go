package v6

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/container"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/kube"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const webhookStrFormat = "apiVersion: v1\nkind: Config\nclusters:\n  - name: elkeid-audit-webhook-server\n    cluster:\n      certificate-authority-data: {certificate-authority-data}\n      server: https://%s/rawdata/audit\n\nusers:\n  - name: k8s-audit-webhook\n    user:\n      client-certificate-data: {client-certificate-data}\n      client-key-data: {client-key-data}\n\ncurrent-context: webhook\ncontexts:\n- context:\n    cluster: elkeid-audit-webhook-server\n    user: k8s-audit-webhook\n  name: webhook"

// 新增集群配置
func NewClusterConfig(c *gin.Context) {
	var clusterConfig container.ClusterConfig

	// 绑定筛选数据
	err := c.BindJSON(&clusterConfig)
	if err != nil {
		ylog.Errorf("NewClusterConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, "error")
		return
	}

	// 记录创建用户
	createUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	clusterConfig.User = createUser.(string)
	clusterConfig.ClusterId = uuid.NewString()
	clusterConfig.CreateTime = time.Now().Unix()

	// 连接k8s 获取状态
	_, err = container.GetKubeClientSet(clusterConfig.KubeConfig)
	if err != nil {
		clusterConfig.ClusterStatus = container.ClusterStatusError
		clusterConfig.ErrReason = err.Error()
	} else {
		clusterConfig.ClusterStatus = container.ClusterStatusRunning
	}

	// 初始化组件状态
	clusterConfig.ModuleStatus.Threat = container.ClusterModuleInactive
	clusterConfig.ModuleStatus.Exposure = container.ClusterModuleInactive

	// 新增配置
	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	_, err = kubeConfCol.InsertOne(c, clusterConfig)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	go container.SetKubeData("once")
	time.Sleep(time.Duration(500) * time.Millisecond)
	common.CreateResponse(c, common.SuccessCode, nil)
}

// 删除集群配置
func DelClusterConfig(c *gin.Context) {
	// 绑定组件信息
	var request struct {
		IdList []string `json:"id_list"`
	}

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("DelClusterConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, "no id")
		return
	}

	if len(request.IdList) == 0 {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "id_list can not empty")
		return
	}

	// 删除配置
	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	_, err = kubeConfCol.DeleteMany(c, bson.M{"cluster_id": bson.M{"$in": request.IdList}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	// 删除集群信息
	kubeInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	_, err = kubeInfoCol.DeleteMany(c, bson.M{"cluster_id": bson.M{"$in": request.IdList}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	go container.SetKubeData("once")
	time.Sleep(time.Duration(500) * time.Millisecond)
	common.CreateResponse(c, common.SuccessCode, nil)
}

// 编辑集群配置名称
func RenameClusterConfig(c *gin.Context) {
	// 绑定组件信息
	var request struct {
		ClusterId   string `json:"cluster_id"`
		ClusterName string `json:"cluster_name"`
	}

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("RenameClusterConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, "error")
		return
	}

	// 重命名
	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	_, err = kubeConfCol.UpdateOne(c, bson.M{"cluster_id": request.ClusterId}, bson.M{"$set": bson.M{"cluster_name": request.ClusterName}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	time.Sleep(time.Duration(500) * time.Millisecond)
	common.CreateResponse(c, common.SuccessCode, nil)
}

// 查询cluster配置列表
type ClusterConfigApi struct {
	ClusterId     string `json:"cluster_id" bson:"cluster_id"`
	ClusterName   string `json:"cluster_name" bson:"cluster_name"`
	ClusterRegion string `json:"cluster_region" bson:"cluster_region"`
	ClusterStatus string `json:"cluster_status" bson:"cluster_status"`
	CreateTime    int64  `json:"create_time" bson:"create_time"`
	KubeConfig    string `json:"kube_config" bson:"kube_config"`
	User          string `json:"user" bson:"user"`
	ErrReason     string `json:"err_reason" bson:"err_reason"`
	ModuleStatus  struct {
		Threat      container.ClusterModuleStatus `json:"threat" bson:"threat"`
		Application container.ClusterModuleStatus `json:"application" bson:"application"`
		Baseline    container.ClusterModuleStatus `json:"baseline" bson:"baseline"`
		Exposure    container.ClusterModuleStatus `json:"exposure" bson:"exposure"`
	} `json:"module_status" bson:"module_status"`
}

func GetClusterConfigList(c *gin.Context) {
	var request struct {
		ClusterName       string   `json:"cluster_name" bson:"cluster_name"`
		ClusterRegion     string   `json:"cluster_region" bson:"cluster_region"`
		ClusterStatusList []string `json:"cluster_status_list" bson:"cluster_status_list"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetClusterConfigList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetClusterConfigList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if len(request.ClusterStatusList) != 0 {
		searchFilter["cluster_status"] = common.MongoInside{Inside: request.ClusterStatusList}
	}
	if request.ClusterName != "" {
		searchFilter["cluster_name"] = common.MongoRegex{Regex: request.ClusterName}
	}
	if request.ClusterRegion != "" {
		searchFilter["cluster_region"] = common.MongoRegex{Regex: request.ClusterRegion}
	}

	// 拼接分页数据s
	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]ClusterConfigApi, 0)
	pageResponse, err := common.DBSearchPaginate(
		kubeConfCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var clusterConfig container.ClusterConfig
			err := cursor.Decode(&clusterConfig)
			if err != nil {
				ylog.Errorf("GetClusterConfigList", err.Error())
				return err
			}
			clusterConfigApi := ClusterConfigApi{
				ClusterName:   clusterConfig.ClusterName,
				ClusterId:     clusterConfig.ClusterId,
				ClusterRegion: clusterConfig.ClusterRegion,
				ClusterStatus: clusterConfig.ClusterStatus,
				CreateTime:    clusterConfig.CreateTime,
				KubeConfig:    clusterConfig.KubeConfig,
				User:          clusterConfig.User,
				ErrReason:     clusterConfig.ErrReason,
			}
			clusterConfigApi.ModuleStatus.Threat.Status = clusterConfig.ModuleStatus.Threat
			clusterConfigApi.ModuleStatus.Application.Status = clusterConfig.ModuleStatus.Application
			clusterConfigApi.ModuleStatus.Baseline.Status = clusterConfig.ModuleStatus.Baseline
			clusterConfigApi.ModuleStatus.Exposure.Status = clusterConfig.ModuleStatus.Exposure
			if clusterConfigApi.ModuleStatus.Exposure.Status == "" {
				clusterConfigApi.ModuleStatus.Exposure.Status = container.ClusterModuleInactive
			}
			if clusterConfigApi.ClusterStatus != "error" {
				clusterConfigApi.ErrReason = ""
			}
			dataResponse = append(dataResponse, clusterConfigApi)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetClusterConfigList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 获取容器集群列表
func GetClusterList(c *gin.Context) {
	var request struct {
		ClusterName   string `json:"cluster_name" bson:"cluster_name"`
		ClusterRegion string `json:"cluster_region" bson:"cluster_region"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetClusterList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetClusterList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if request.ClusterName != "" {
		searchFilter["cluster_name"] = common.MongoRegex{Regex: request.ClusterName}
	}
	if request.ClusterRegion != "" {
		searchFilter["cluster_region"] = common.MongoRegex{Regex: request.ClusterRegion}
	}

	// 拼接分页数据s
	kubeClusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]container.ClusterInfo, 0)
	pageResponse, err := common.DBSearchPaginate(
		kubeClusterCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var clusterInfo container.ClusterInfo
			err := cursor.Decode(&clusterInfo)
			if err != nil {
				ylog.Errorf("GetClusterList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, clusterInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetClusterList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)

}

// 查询集群信息(包含统计信息)
func GetClusterInfo(c *gin.Context) {

	var request struct {
		ClusterId string `json:"cluster_id" bson:"cluster_id"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetClusterInfo", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	var clusterInfo container.ClusterInfo
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	err = collection.FindOne(c, bson.M{"cluster_id": request.ClusterId}).Decode(&clusterInfo)
	if err != nil {
		ylog.Errorf("GetClusterInfo", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, clusterInfo)
}

// 获取集群节点列表
func GetNodeList(c *gin.Context) {
	var request struct {
		ClusterId  string   `json:"cluster_id" bson:"cluster_id"`
		NodeName   string   `json:"node_name" bson:"node_name"`
		NodeStatus []string `json:"node_status" bson:"node_status"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetNodeList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetNodeList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.ClusterId
	if request.NodeName != "" {
		searchFilter["node_name"] = common.MongoRegex{Regex: request.NodeName}
	}
	if len(request.NodeStatus) != 0 {
		searchFilter["node_status"] = common.MongoInside{Inside: request.NodeStatus}
	}

	// 拼接分页数据s
	kubeNodeCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeNodeInfo)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]container.ClusterNodeInfo, 0)
	pageResponse, err := common.DBSearchPaginate(
		kubeNodeCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var clusterNodeInfo container.ClusterNodeInfo
			err := cursor.Decode(&clusterNodeInfo)
			if err != nil {
				ylog.Errorf("GetNodeList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, clusterNodeInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetNodeList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)

}

// 获取工作负载列表
func GetWorkerList(c *gin.Context) {
	var request struct {
		ClusterId  string   `json:"cluster_id" bson:"cluster_id"`
		WorkerName string   `json:"worker_name" bson:"worker_name"`
		WorkerType []string `json:"worker_type" bson:"worker_type"`
		Namespace  string   `json:"namespace" bson:"namespace"`
		StartTime  int64    `json:"start_time" bson:"start_time"`
		EndTime    int64    `json:"end_time" bson:"end_time"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetWorkerList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetWorkerList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.ClusterId
	if request.WorkerName != "" {
		searchFilter["worker_name"] = common.MongoRegex{Regex: request.WorkerName}
	}
	if request.Namespace != "" {
		searchFilter["namespace"] = common.MongoRegex{Regex: request.Namespace}
	}
	if len(request.WorkerType) != 0 {
		searchFilter["worker_type"] = common.MongoInside{Inside: request.WorkerType}
	}
	if request.StartTime != 0 {
		searchFilter["start_time"] = common.MongoGte{Value: request.StartTime}
	}
	if request.EndTime != 0 {
		searchFilter["EndTime"] = common.MongoLte{Value: request.EndTime}
	}

	// 拼接分页数据s
	kubeWorkerCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeWorkerInfo)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]container.ClusterWorkerInfo, 0)
	pageResponse, err := common.DBSearchPaginate(
		kubeWorkerCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var clusterWorkerInfo container.ClusterWorkerInfo
			err := cursor.Decode(&clusterWorkerInfo)
			if err != nil {
				ylog.Errorf("GetWorkerList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, clusterWorkerInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetWorkerList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)

}

// 获取容器组列表
func GetPodList(c *gin.Context) {
	var request struct {
		ClusterId string   `json:"cluster_id" bson:"cluster_id"`
		PodName   string   `json:"pod_name" bson:"pod_name"`
		PodStatus []string `json:"pod_status" bson:"pod_status"`
		Namespace string   `json:"namespace" bson:"namespace"`
		PodIp     string   `json:"pod_ip" bson:"pod_ip"`
		NodeIp    string   `json:"node_ip" bson:"node_ip"`
		NodeName  string   `json:"node_name" bson:"node_name"`
		StartTime int64    `json:"start_time" bson:"start_time"`
		EndTime   int64    `json:"end_time" bson:"end_time"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetPodList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetPodList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.ClusterId
	if request.PodName != "" {
		searchFilter["pod_name"] = common.MongoRegex{Regex: request.PodName}
	}
	if request.Namespace != "" {
		searchFilter["namespace"] = common.MongoRegex{Regex: request.Namespace}
	}
	if request.PodIp != "" {
		searchFilter["pod_ip"] = common.MongoRegex{Regex: request.PodIp}
	}
	if request.NodeIp != "" {
		searchFilter["node_ip"] = common.MongoRegex{Regex: request.NodeIp}
	}
	if request.NodeName != "" {
		searchFilter["node_name"] = common.MongoRegex{Regex: request.NodeName}
	}
	if len(request.PodStatus) != 0 {
		searchFilter["pod_status"] = common.MongoInside{Inside: request.PodStatus}
	}
	if request.StartTime != 0 {
		searchFilter["start_time"] = common.MongoGte{Value: request.StartTime}
	}
	if request.EndTime != 0 {
		searchFilter["EndTime"] = common.MongoLte{Value: request.EndTime}
	}

	// 拼接分页数据s
	kubePodCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubePodInfo)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]container.ClusterPodInfo, 0)
	pageResponse, err := common.DBSearchPaginate(
		kubePodCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var clusterPodInfo container.ClusterPodInfo
			err := cursor.Decode(&clusterPodInfo)
			if err != nil {
				ylog.Errorf("GetPodList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, clusterPodInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetPodList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)

}

// 获取容器列表
func GetContainerList(c *gin.Context) {
	var request struct {
		ClusterId     string `json:"cluster_id" bson:"cluster_id"`
		PodId         string `json:"pod_id" bson:"pod_id"`
		ContainerName string `json:"container_name"  bson:"container_name"`
		Image         string `json:"image" bson:"image"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetContainerList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetContainerList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.ClusterId
	searchFilter["pod_id"] = request.PodId
	if request.ContainerName != "" {
		searchFilter["container_name"] = common.MongoRegex{Regex: request.ContainerName}
	}
	if request.Image != "" {
		searchFilter["image"] = common.MongoRegex{Regex: request.Image}
	}

	// 拼接分页数据s
	kubeContainerCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeContainerInfo)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]container.ClusterContainerInfo, 0)
	pageResponse, err := common.DBSearchPaginate(
		kubeContainerCol,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var clusterContainerInfo container.ClusterContainerInfo
			err := cursor.Decode(&clusterContainerInfo)
			if err != nil {
				ylog.Errorf("GetContainerList", err.Error())
				return err
			}
			dataResponse = append(dataResponse, clusterContainerInfo)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetContainerList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)

}

// 获取集群ID(hub调用)
func GetClusterNameFromId(c *gin.Context) {
	var err error
	request := struct {
		Id string `json:"id" form:"id"`
	}{}
	err = c.BindQuery(&request)
	if request.Id == "" {
		request.Id = "get id is empty"
	}
	clusterInfo := struct {
		Cluster     string `json:"cluster" bson:"cluster_name"`
		ClusterArea string `json:"cluster_area" bson:"cluster_region"`
	}{
		Cluster:     request.Id,
		ClusterArea: request.Id,
	}
	if err != nil {
		ylog.Errorf("GetClusterNameFromId", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, clusterInfo)
		return
	}
	if request.Id == "" {
		common.CreateResponse(c, common.ParamInvalidErrorCode, clusterInfo)
		return
	}
	kubeConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterConfig)
	err = kubeConfCol.FindOne(c, bson.M{"cluster_id": request.Id}).Decode(&clusterInfo)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, clusterInfo)
		return
	}
	if clusterInfo.Cluster == "" {
		common.CreateResponse(c, common.DBOperateErrorCode, clusterInfo)
		return
	}
	common.CreateResponse(c, common.SuccessCode, clusterInfo)
}

// 导出集群数据
func ClusterDownload(c *gin.Context) {
	request := struct {
		IdList     []string `json:"id_list" bson:"id_list"`
		Conditions struct {
			ClusterName   string `json:"cluster_name" bson:"cluster_name"`
			ClusterRegion string `json:"cluster_region" bson:"cluster_region"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	searchFilter := make(map[string]interface{})
	if len(request.IdList) != 0 {
		searchFilter["cluster_id"] = common.MongoInside{Inside: request.IdList}
	}
	if request.Conditions.ClusterName != "" {
		searchFilter["cluster_name"] = common.MongoRegex{Regex: request.Conditions.ClusterName}
	}
	if request.Conditions.ClusterRegion != "" {
		searchFilter["cluster_region"] = common.MongoRegex{Regex: request.Conditions.ClusterRegion}
	}

	cursor, err := clusterCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var exportList [][]string
	for cursor.Next(c) {
		var clusterInfo container.ClusterInfo
		_ = cursor.Decode(&clusterInfo)

		exportData := make([]string, 0, 9)

		exportData = append(exportData, clusterInfo.ClusterId)
		exportData = append(exportData, clusterInfo.ClusterName)
		exportData = append(exportData, clusterInfo.ClusterVersion)
		exportData = append(exportData, clusterInfo.ClusterRegion)
		exportData = append(exportData, strconv.FormatInt(clusterInfo.NodeNum, 10))
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "cluster_id", Header: "cluster_id"},
		{Key: "cluster_name", Header: "cluster_name"},
		{Key: "cluster_version", Header: "cluster_version"},
		{Key: "cluster_region", Header: "cluster_region"},
		{Key: "node_num", Header: "node_num"},
	}

	filename := "cluster_info" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 导出集群节点数据
func NodeDownload(c *gin.Context) {
	request := struct {
		IdList     []string `json:"id_list" bson:"id_list"`
		Conditions struct {
			ClusterId  string   `json:"cluster_id" bson:"cluster_id"`
			NodeName   string   `json:"node_name" bson:"node_name"`
			NodeStatus []string `json:"node_status" bson:"node_status"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.Conditions.ClusterId
	if len(request.IdList) != 0 {
		searchFilter["node_id"] = common.MongoInside{Inside: request.IdList}
	}
	if request.Conditions.NodeName != "" {
		searchFilter["node_name"] = common.MongoRegex{Regex: request.Conditions.NodeName}
	}
	if len(request.Conditions.NodeStatus) != 0 {
		searchFilter["node_status"] = common.MongoInside{Inside: request.Conditions.NodeStatus}
	}
	cursor, err := clusterCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var exportList [][]string
	for cursor.Next(c) {
		var clusterNodeInfo container.ClusterNodeInfo
		_ = cursor.Decode(&clusterNodeInfo)

		exportData := make([]string, 0, 9)

		exportData = append(exportData, clusterNodeInfo.NodeId)
		exportData = append(exportData, clusterNodeInfo.NodeName)
		exportData = append(exportData, clusterNodeInfo.NodeStatus)
		exportData = append(exportData, clusterNodeInfo.NodeRole)
		exportData = append(exportData, clusterNodeInfo.NodeVersion)
		exportData = append(exportData, clusterNodeInfo.IntranetIp)
		exportData = append(exportData, clusterNodeInfo.ExtranetIp)
		exportData = append(exportData, clusterNodeInfo.SystemImage)
		exportData = append(exportData, clusterNodeInfo.KernelVersion)
		exportData = append(exportData, clusterNodeInfo.Runtime)
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "node_id", Header: "node_id"},
		{Key: "node_name", Header: "node_name"},
		{Key: "node_status", Header: "node_status"},
		{Key: "node_role", Header: "node_role"},
		{Key: "node_version", Header: "node_version"},
		{Key: "intranet_ip", Header: "intranet_ip"},
		{Key: "extranet_ip", Header: "extranet_ip"},
		{Key: "system_image", Header: "system_image"},
		{Key: "kernel_version", Header: "kernel_version"},
		{Key: "runtime", Header: "runtime"},
	}

	filename := "node_info" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 导出集群工作负载数据
func WorkerDownload(c *gin.Context) {
	request := struct {
		IdList     []string `json:"id_list" bson:"id_list"`
		Conditions struct {
			ClusterId  string   `json:"cluster_id" bson:"cluster_id"`
			WorkerName string   `json:"worker_name" bson:"worker_name"`
			WorkerType []string `json:"worker_type" bson:"worker_type"`
			Namespace  string   `json:"namespace" bson:"namespace"`
			StartTime  int64    `json:"start_time" bson:"start_time"`
			EndTime    int64    `json:"end_time" bson:"end_time"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.Conditions.ClusterId
	if len(request.IdList) != 0 {
		searchFilter["worker_id"] = common.MongoInside{Inside: request.IdList}
	}
	if request.Conditions.WorkerName != "" {
		searchFilter["worker_name"] = common.MongoRegex{Regex: request.Conditions.WorkerName}
	}
	if request.Conditions.Namespace != "" {
		searchFilter["namespace"] = common.MongoRegex{Regex: request.Conditions.Namespace}
	}
	if len(request.Conditions.WorkerType) != 0 {
		searchFilter["worker_type"] = common.MongoInside{Inside: request.Conditions.WorkerType}
	}
	if request.Conditions.StartTime != 0 {
		searchFilter["start_time"] = common.MongoGte{Value: request.Conditions.StartTime}
	}
	if request.Conditions.EndTime != 0 {
		searchFilter["EndTime"] = common.MongoLte{Value: request.Conditions.EndTime}
	}
	cursor, err := clusterCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var exportList [][]string
	for cursor.Next(c) {
		var clusterWorkerInfo container.ClusterWorkerInfo
		_ = cursor.Decode(&clusterWorkerInfo)

		exportData := make([]string, 0, 9)

		exportData = append(exportData, clusterWorkerInfo.WorkerId)
		exportData = append(exportData, clusterWorkerInfo.WorkerName)
		exportData = append(exportData, clusterWorkerInfo.WorkerType)
		exportData = append(exportData, clusterWorkerInfo.Namespace)
		exportData = append(exportData, strconv.FormatInt(clusterWorkerInfo.CreateTime, 10))
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "worker_id", Header: "worker_id"},
		{Key: "worker_name", Header: "worker_name"},
		{Key: "worker_type", Header: "worker_type"},
		{Key: "namespace", Header: "namespace"},
		{Key: "create_time", Header: "create_time"},
	}

	filename := "worker_info" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 导出集群容器组数据
func PodDownload(c *gin.Context) {
	request := struct {
		IdList     []string `json:"id_list" bson:"id_list"`
		Conditions struct {
			ClusterId string `json:"cluster_id" bson:"cluster_id"`
			PodName   string `json:"pod_name" bson:"pod_name"`
			PodStatus string `json:"pod_status" bson:"pod_status"`
			Namespace string `json:"namespace" bson:"namespace"`
			PodIp     string `json:"pod_ip" bson:"pod_ip"`
			NodeIp    string `json:"node_ip" bson:"node_ip"`
			NodeName  string `json:"node_name" bson:"node_name"`
			StartTime int64  `json:"start_time" bson:"start_time"`
			EndTime   int64  `json:"end_time" bson:"end_time"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.Conditions.ClusterId
	if len(request.IdList) != 0 {
		searchFilter["pod_id"] = common.MongoInside{Inside: request.IdList}
	}
	if request.Conditions.PodName != "" {
		searchFilter["pod_name"] = common.MongoRegex{Regex: request.Conditions.PodName}
	}
	if request.Conditions.Namespace != "" {
		searchFilter["namespace"] = common.MongoRegex{Regex: request.Conditions.Namespace}
	}
	if request.Conditions.PodIp != "" {
		searchFilter["pod_ip"] = common.MongoRegex{Regex: request.Conditions.PodIp}
	}
	if request.Conditions.NodeIp != "" {
		searchFilter["node_ip"] = common.MongoRegex{Regex: request.Conditions.NodeIp}
	}
	if request.Conditions.NodeName != "" {
		searchFilter["node_name"] = common.MongoRegex{Regex: request.Conditions.NodeName}
	}
	if len(request.Conditions.PodStatus) != 0 {
		searchFilter["pod_status"] = common.MongoInside{Inside: request.Conditions.PodStatus}
	}
	if request.Conditions.StartTime != 0 {
		searchFilter["start_time"] = common.MongoGte{Value: request.Conditions.StartTime}
	}
	if request.Conditions.EndTime != 0 {
		searchFilter["EndTime"] = common.MongoLte{Value: request.Conditions.EndTime}
	}
	cursor, err := clusterCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var exportList [][]string
	for cursor.Next(c) {
		var clusterPodInfo container.ClusterPodInfo
		_ = cursor.Decode(&clusterPodInfo)

		exportData := make([]string, 0, 9)

		exportData = append(exportData, clusterPodInfo.PodId)
		exportData = append(exportData, clusterPodInfo.PodName)
		exportData = append(exportData, clusterPodInfo.PodStatus)
		exportData = append(exportData, clusterPodInfo.PodIp)
		exportData = append(exportData, clusterPodInfo.NodeIp)
		exportData = append(exportData, clusterPodInfo.Namespace)
		exportData = append(exportData, clusterPodInfo.NodeName)
		exportData = append(exportData, strconv.FormatInt(clusterPodInfo.CreateTime, 10))
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "pod_id", Header: "pod_id"},
		{Key: "pod_name", Header: "pod_name"},
		{Key: "pod_status", Header: "pod_status"},
		{Key: "pod_ip", Header: "pod_ip"},
		{Key: "node_ip", Header: "node_ip"},
		{Key: "namespace", Header: "namespace"},
		{Key: "node_name", Header: "node_name"},
		{Key: "create_time", Header: "create_time"},
	}

	filename := "pod_info" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

// 导出容器负载数据
func ContainerDownload(c *gin.Context) {
	request := struct {
		IdList     []string `json:"id_list" bson:"id_list"`
		Conditions struct {
			ClusterId     string `json:"cluster_id" bson:"cluster_id"`
			PodId         string `json:"pod_id" bson:"pod_id"`
			ContainerName string `json:"container_name"  bson:"container_name"`
			Image         string `json:"image" bson:"image"`
		} `json:"conditions" bson:"conditions"`
	}{}

	err := c.BindJSON(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, nil)
		return
	}

	clusterCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.KubeClusterInfo)
	searchFilter := make(map[string]interface{})
	searchFilter["cluster_id"] = request.Conditions.ClusterId
	searchFilter["pod_id"] = request.Conditions.PodId
	if len(request.IdList) != 0 {
		searchFilter["container_id"] = common.MongoInside{Inside: request.IdList}
	}
	if request.Conditions.ContainerName != "" {
		searchFilter["container_name"] = common.MongoRegex{Regex: request.Conditions.ContainerName}
	}
	if request.Conditions.Image != "" {
		searchFilter["image"] = common.MongoRegex{Regex: request.Conditions.Image}
	}
	cursor, err := clusterCol.Find(c, searchFilter)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var exportList [][]string
	for cursor.Next(c) {
		var clusterContainerInfo container.ClusterContainerInfo
		_ = cursor.Decode(&clusterContainerInfo)

		exportData := make([]string, 0, 9)

		exportData = append(exportData, clusterContainerInfo.ContainerId)
		exportData = append(exportData, clusterContainerInfo.ContainerName)
		exportData = append(exportData, clusterContainerInfo.Image)
		exportList = append(exportList, exportData)
	}

	// 导出数据
	var header = common.MongoDBDefs{
		{Key: "container_id", Header: "container_id"},
		{Key: "container_name", Header: "container_name"},
		{Key: "image", Header: "image"},
	}

	filename := "container_info" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}

func PolicyDownload(c *gin.Context) {
	policy := "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages:\n  - \"RequestReceived\"\nrules:\n  # [+] Record sensitive resource creation request events at request level.\n  # (For threat detection.)\n  - level: RequestResponse\n    verbs: [\"create\", \"update\", \"patch\"]\n    resources:\n      - group: \"\"\n        resources: [\"pods\", \"services\", \"replicationcontrollers\"]\n      - group: \"apps\"\n        resources: [\"daemonsets\", \"deployments\", \"replicasets\", \"statefulsets\"]\n      - group: \"batch\"\n        resources: [\"cronjobs\", \"jobs\"]\n      - group: \"networking.k8s.io\"\n        resources: [\"ingresses\"]\n\n  # [+] Record RBAC resource creation request events at request level.\n  # (For threat detection.)\n  - level: Request\n    verbs: [\"create\", \"patch\", \"update\"]\n    resources:\n    - group: \"rbac.authorization.k8s.io\"\n      resources: [\"clusterroles\", \"clusterrolebindings\", \"roles\", \"rolebindings\"]\n\n  # The following requests were manually identified as high-volume and low-risk,\n  # so drop them.\n  - level: None\n    users: [\"system:kube-proxy\", \"system:serviceaccount:kube-system:kube-proxy\"]\n    verbs: [\"watch\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"endpoints\", \"services\", \"services/status\"]\n\n  - level: None\n    users: [\"kubelet\"] # legacy kubelet identity\n    verbs: [\"get\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"nodes\", \"nodes/status\"]\n\n  - level: None\n    userGroups: [\"system:nodes\"]\n    verbs: [\"get\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"nodes\", \"nodes/status\"]\n\n  - level: None\n    users: [\"system:serviceaccount:kube-system:generic-garbage-collector\"]\n    verbs: [\"get\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"nodes\"]\n\n  - level: None\n    users:\n      - system:kube-controller-manager\n      - system:kube-scheduler\n      - system:serviceaccount:kube-system:endpoint-controller\n    verbs: [\"get\", \"update\"]\n    namespaces: [\"kube-system\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"endpoints\"]\n      - group: \"coordination.k8s.io\"\n        resources: [\"leases\"]\n\n  - level: None\n    users:\n      - system:kube-scheduler\n    verbs: [\"watch\"]\n    resources:\n      - group: \"\" #core\n        resources: [\"nodes\", \"pods\", \"configmaps\"]\n      - group: \"apps\"\n        resources: [\"statefulsets\"]\n      - group: \"storage.k8s.io\"\n        resources: [\"csinodes\", \"csistoragecapacities\"]\n\n  - level: None\n    users:\n      - system:kube-scheduler\n    verbs: [\"list\"]\n    resources:\n      - group: \"storage.k8s.io\"\n        resources: [\"csistoragecapacities\"]\n\n  - level: None\n    userGroups: [\"system:nodes\"]\n    verbs: [\"update\"]\n    namespaces: [\"kube-node-lease\"]\n    resources:\n      - group: \"coordination.k8s.io\"\n        resources: [\"leases\"]\n\n  - level: None\n    users: [\"system:kube-controller-manager\"]\n    verbs: [\"watch\"]\n    resources:\n      - group: \"\" #core\n        resources: [\"configmaps\", \"endpoints\", \"namespaces\", \"nodes\", \"limitranges\", \"persistentvolumes\", \"pods\", \"podtemplates\", \"replicationcontrollers\", \"resourcequotas\", \"serviceaccounts\", \"secrets\"]\n      - group: \"admissionregistration.k8s.io\"\n        resources: [\"mutatingwebhookconfigurations\"]\n      - group: \"apiextensions.k8s.io\"\n        resources: [\"customresourcedefinitions\"]\n      - group: \"apps\"\n        resources: [\"controllerrevisions\", \"daemonsets\", \"replicasets\", \"statefulsets\"]\n      - group: \"apiregistration.k8s.io\"\n        resources: [\"apiservices\"]\n      - group: \"autoscaling\"\n        resources: [\"horizontalpodautoscalers\"]\n      - group: \"batch\"\n        resources: [\"cronjobs\", \"jobs\"]\n      - group: \"certificates.k8s.io\"\n        resources: [\"certificatesigningrequests\"]\n      - group: \"coordination.k8s.io\"\n        resources: [\"leases\"]\n      - group: \"flowcontrol.apiserver.k8s.io\"\n        resources: [\"prioritylevelconfigurations\"]\n      - group: \"networking.k8s.io\"\n        resources: [\"networkpolicies\", \"ingressclasses\"]\n      - group: \"policy\"\n        resources: [\"poddisruptionbudgets\", \"podsecuritypolicies\"]\n      - group: \"rbac.authorization.k8s.io\"\n        resources: [\"clusterrolebindings\", \"roles\", \"rolebindings\"]\n      - group: \"storage.k8s.io\"\n        resources: [\"csinodes\", \"volumeattachments\"]\n\n  - level: None\n    users: [\"system:kube-controller-manager\"]\n    verbs: [\"get\"]\n    resources:\n      - group: \"\" #core\n        resources: [\"serviceaccounts\"]\n\n  - level: None\n    users: [\"system:serviceaccount:kube-system:coredns\"]\n    verbs: [\"watch\"]\n    resources:\n      - group: \"\" #core\n        resources: [\"namespaces\", \"services\"]\n      - group: \"discovery.k8s.io\"\n        resources: [\"endpointslices\"]\n\n  - level: None\n    users: [\"system:apiserver\"]\n    verbs: [\"get\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"services\", \"endpoints\", \"namespaces\", \"namespaces/status\", \"namespaces/finalize\"]\n      - group: \"discovery.k8s.io\"\n        resources: [\"endpointslices\"]\n\n  - level: None\n    users: [\"system:apiserver\"]\n    verbs: [\"watch\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"limitranges\", \"nodes\", \"persistentvolumes\", \"secrets\", \"configmaps\"]\n      - group: \"flowcontrol.apiserver.k8s.io\"\n        resources: [\"flowschemas\", \"prioritylevelconfigurations\"]\n      - group: \"admissionregistration.k8s.io\"\n        resources: [\"mutatingwebhookconfigurations\", \"validatingwebhookconfigurations\"]\n      - group: \"networking.k8s.io\"\n        resources: [\"ingresses\"]\n      - group: \"rbac.authorization.k8s.io\"\n        resources: [\"clusterroles\", \"clusterrolebindings\", \"roles\", \"rolebindings\"]\n\n  - level: None\n    users: [\"cluster-autoscaler\"]\n    verbs: [\"get\", \"update\"]\n    namespaces: [\"kube-system\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"configmaps\", \"endpoints\"]\n\n  # Don't log HPA fetching metrics.\n  - level: None\n    users:\n      - system:kube-controller-manager\n    verbs: [\"get\", \"list\"]\n    resources:\n      - group: \"metrics.k8s.io\"\n\n  # Don't log these read-only URLs.\n  - level: None\n    nonResourceURLs:\n      - /healthz*\n      - /version\n      - /swagger*\n      - /readyz*\n      - /livez*\n      - /api*\n\n  # Don't log events requests because of performance impact.\n  - level: None\n    resources:\n      - group: \"\" # core\n        resources: [\"events\"]\n\n  # node and pod status calls from nodes are high-volume and can be large, don't log responses for expected updates from nodes\n  - level: Request  # CAN SET TO None\n    users: [\"kubelet\", \"system:node-problem-detector\", \"system:serviceaccount:kube-system:node-problem-detector\"]\n    verbs: [\"update\",\"patch\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"nodes/status\", \"pods/status\"]\n\n  - level: Request  # CAN SET TO None\n    userGroups: [\"system:nodes\"]\n    verbs: [\"update\",\"patch\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"nodes/status\", \"pods/status\"]\n\n  - level: None\n    userGroups: [\"system:nodes\"]\n    verbs: [\"update\",\"patch\", \"watch\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"nodes\"]\n\n  - level: None\n    userGroups: [\"system:nodes\"]\n    verbs: [\"watch\"]\n    resources:\n      - group: \"\" # core\n        resources: [\"configmaps\", \"pods\", \"services\"]\n      - group: \"storage.k8s.io\"\n        resources: [\"csidrivers\"]\n      - group: \"node.k8s.io\"\n        resources: [\"runtimeclasses\"]\n\n  # Default level for all other requests.\n  - level: Metadata\n    omitStages:\n      - \"RequestReceived\""

	c.Header("Content-Disposition", "attachment; filename="+"\"audit-policy.yaml\"")
	c.Data(http.StatusOK, "application/octet-stream", []byte(policy))
}
func WebhookDownload(c *gin.Context) {
	request := struct {
		ClusterId string `json:"cluster_id" bson:"cluster_id" form:"cluster_id"`
	}{}
	err := c.BindQuery(&request)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if request.ClusterId == "" {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "cluster_id can not empty")
		return
	}

	k8sServer := "elkeid.com:6754"
	if len(monitor.Config.AC.SSHHost) > 0 {
		k8sServer = monitor.Config.AC.SSHHost[0].Host + ":6754"
	}
	webhookStr := fmt.Sprintf(webhookStrFormat, k8sServer)

	cacert := kube.LoadCaCert()
	key, cert, err := kube.CreateCert(request.ClusterId, 24*365*10*time.Hour)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}
	key_base64 := base64.StdEncoding.EncodeToString(key)
	cert_base64 := base64.StdEncoding.EncodeToString(cert)
	cacert_base64 := base64.StdEncoding.EncodeToString(cacert)
	webhookStr = strings.Replace(webhookStr, "{certificate-authority-data}", cacert_base64, 1)
	webhookStr = strings.Replace(webhookStr, "{client-certificate-data}", cert_base64, 1)
	webhookStr = strings.Replace(webhookStr, "{client-key-data}", key_base64, 1)

	c.Header("Content-Disposition", "attachment; filename="+"\"audit.kubeconfig\"")
	c.Data(http.StatusOK, "application/octet-stream", []byte(webhookStr))
}

func KubeCreateShDownload(c *gin.Context) {
	policy := "#! /bin/bash\n\nUSER_NAME=elkeid-cwpp-console\nGROUP_NAME=security:elkeid\nCERTIFICATE_NAME=$USER_NAME\nEXPIRATION_SECONDS=$((1*60*60*24*365))\n\nusage()\n{\n    echo \"Usage:\n    ./create-kubeconfig-for-elkeid-cwpp.sh CLUSTER_NAME CLUSTER_AREA SERVER_URL CA_CERT_PATH [KUBECONFIG_PATH]\n\n    CLUSTER_NAME: The cluster name you want to use in Elkeid console.\n    CLUSTER_AREA: The cluster area you want to use in Elkeid console.\n    SERVER_URL: The address of APIServer. (Example: https://192.168.1.3:6443)\n    CA_CERT_PATH: The CA certificate of APIServer. (Example:/etc/kubernetes/pki/ca.crt)\n    KUBECONFIG_PATH: Optional. The kubeconfig with admin rights for accessing the APIServer.\n    \n(Note: You must make sure that KUBECONFIG environment variable points to the target cluster's kubeconfig when you don't specify the KUBECONFIG_PATH parameter.)\"\n    exit 1\n}\n\ndelete_already_exist_csr()\n{\n    kubectl --kubeconfig=$KUBECONFIG_PATH get CertificateSigningRequest $1 1>/dev/null 2>/dev/null\n    if [ $? == 0 ] ; then\n        kubectl --kubeconfig=$KUBECONFIG_PATH delete CertificateSigningRequest $1\n    fi\n}\n\ndelete_already_exist_cr_and_crb()\n{\n    kubectl --kubeconfig=$KUBECONFIG_PATH get ClusterRole elkeid-cwpp-console 1>/dev/null 2>/dev/null\n    if [ $? == 0 ] ; then\n        kubectl --kubeconfig=$KUBECONFIG_PATH delete ClusterRole elkeid-cwpp-console\n    fi\n\n    kubectl --kubeconfig=$KUBECONFIG_PATH get ClusterRoleBinding elkeid-cwpp-console 1>/dev/null 2>/dev/null\n    if [ $? == 0 ] ; then\n        kubectl --kubeconfig=$KUBECONFIG_PATH delete ClusterRoleBinding elkeid-cwpp-console\n    fi\n}\n\ndelete_already_exist_r_and_rb()\n{\n    kubectl --kubeconfig=$KUBECONFIG_PATH get Role elkeid-cwpp-console -n elkeid 1>/dev/null 2>/dev/null\n    if [ $? == 0 ] ; then\n        kubectl --kubeconfig=$KUBECONFIG_PATH delete Role elkeid-cwpp-console -n elkeid\n    fi\n\n    kubectl --kubeconfig=$KUBECONFIG_PATH get RoleBinding elkeid-cwpp-console -n elkeid 1>/dev/null 2>/dev/null\n    if [ $? == 0 ] ; then\n        kubectl --kubeconfig=$KUBECONFIG_PATH delete RoleBinding elkeid-cwpp-console -n elkeid\n    fi\n}\n\nmain()\n{\n    # Create client key and cert \n    openssl genrsa -out $USER_NAME.key 2048\n    openssl req -new -key $USER_NAME.key -out $USER_NAME.csr -subj \"/CN=$USER_NAME/O=$GROUP_NAME\"\n\n    # Sign the client certificates\n    CERTIFICATE_NAME=$USER_NAME\n    delete_already_exist_csr $CERTIFICATE_NAME\n    cat <<EOF | kubectl --kubeconfig=$KUBECONFIG_PATH create --validate=false -f 2>/dev/null -\napiVersion: certificates.k8s.io/v1beta1\nkind: CertificateSigningRequest\nmetadata:\n    name: $CERTIFICATE_NAME\nspec:\n    groups:\n    - system:authenticated\n    request: $(cat $USER_NAME.csr | base64 | tr -d '\\n')\n    signerName: kubernetes.io/kube-apiserver-client\n    expirationSeconds: $EXPIRATION_SECONDS\n    usages:\n    - digital signature\n    - key encipherment\n    - client auth\nEOF\n    if [ $? != 0 ] ; then\n      cat <<EOF | kubectl --kubeconfig=$KUBECONFIG_PATH create -f -\napiVersion: certificates.k8s.io/v1\nkind: CertificateSigningRequest\nmetadata:\n    name: $CERTIFICATE_NAME\nspec:\n    groups:\n    - system:authenticated\n    request: $(cat $USER_NAME.csr | base64 | tr -d '\\n')\n    signerName: kubernetes.io/kube-apiserver-client\n    expirationSeconds: $EXPIRATION_SECONDS\n    usages:\n    - digital signature\n    - key encipherment\n    - client auth\nEOF\n    fi\n    kubectl --kubeconfig=$KUBECONFIG_PATH certificate approve $CERTIFICATE_NAME\n    kubectl --kubeconfig=$KUBECONFIG_PATH get csr $CERTIFICATE_NAME -o jsonpath='{.status.certificate}'  | base64 --decode > $USER_NAME.crt\n\n    # Create ClusterRole & ClusterRoleBinding\n    delete_already_exist_cr_and_crb\n    delete_already_exist_r_and_rb\n    cat <<EOF | kubectl --kubeconfig=$KUBECONFIG_PATH create -f -\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: elkeid-cwpp-console\n  labels:\n    app: elkeid-cwpp-console\nrules:\n- apiGroups:\n  - \"\"\n  resources:\n  - nodes\n  - pods\n  - replicationcontrollers\n  - namespaces\n  verbs:\n  - get\n  - list\n  - watch\n\n- apiGroups:\n  - apps\n  resources:\n  - daemonsets\n  - deployments\n  - replicasets\n  - statefulsets\n  verbs:\n  - get\n  - list\n  - watch\n\n- apiGroups:\n  - batch\n  resources:\n  - jobs\n  - cronjobs\n  verbs:\n  - get\n  - list\n  - watch\n\n- apiGroups:\n  - \"apiextensions.k8s.io\"\n  resources:\n  - customresourcedefinitions\n  verbs:\n  - \"*\"\n\n- apiGroups:\n  - \"rbac.authorization.k8s.io\"\n  resources:\n  - clusterrolebindings\n  - clusterroles\n  verbs:\n  - \"*\"\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: elkeid-cwpp-console\n  labels:\n    app: elkeid-cwpp-console\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: elkeid-cwpp-console\nsubjects:\n- apiGroup: rbac.authorization.k8s.io\n  kind: User\n  name: elkeid-cwpp-console\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: elkeid-cwpp-console\n  namespace: elkeid\n  labels:\n    app: elkeid-cwpp-console\nrules:\n- apiGroups:\n  - \"\"\n  resources:\n  - namespaces\n  resourceNames:\n  - elkeid\n  verbs:\n  - \"*\"\n\n- apiGroups:\n  - \"\"\n  resources:\n  - serviceaccounts\n  verbs:\n  - \"*\"\n\n- apiGroups:\n  - \"\"\n  resources:\n  - secrets\n  verbs:\n  - \"*\"\n\n- apiGroups:\n  - \"\"\n  resources:\n  - configmaps\n  verbs:\n  - \"*\"\n\n- apiGroups:\n  - apps\n  resources:\n  - deployments\n  verbs:\n  - \"*\"\n\n- apiGroups:\n  - \"rbac.authorization.k8s.io\"\n  resources:\n  - rolebindings\n  - roles\n  verbs:\n  - \"*\"\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: elkeid-cwpp-console\n  namespace: elkeid\n  labels:\n    app: elkeid-cwpp-console\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: Role\n  name: elkeid-cwpp-console\nsubjects:\n- apiGroup: rbac.authorization.k8s.io\n  kind: User\n  name: elkeid-cwpp-console\n\nEOF\n\n    # Create kubeconfig\n    kubectl config set-cluster $CLUSTER_NAME --server=\"$SERVER_URL\" --certificate-authority=$CA_PATH --embed-certs=true --kubeconfig=$OUTPUT_KUBE_CONFIG\n    kubectl config set-context $CONTEXT_NAME --cluster=$CLUSTER_NAME --user=$USER_NAME --kubeconfig=$OUTPUT_KUBE_CONFIG\n    kubectl config set-credentials $USER_NAME --client-certificate=$USER_NAME.crt --client-key=$USER_NAME.key --embed-certs=true --kubeconfig=$OUTPUT_KUBE_CONFIG\n    kubectl config use-context $CONTEXT_NAME --kubeconfig=$OUTPUT_KUBE_CONFIG\n    rm $USER_NAME.key $USER_NAME.csr $USER_NAME.crt\n    echo \"\"\n    echo \"Done. Please copy and paste the following content.\"\n    echo \"\"\n    cat $OUTPUT_KUBE_CONFIG\n}\n\nif test $# -lt 4\nthen\n   usage\nfi\n\nCLUSTER_NAME=$1-$2\nCONTEXT_NAME=$USER_NAME@$CLUSTER_NAME\nOUTPUT_KUBE_CONFIG=$CLUSTER_NAME.kubeconfig\nSERVER_URL=$3\nCA_PATH=$4\n\nif test $# -ne 5\nthen\n   KUBECONFIG_PATH=$KUBECONFIG\nelse\n   KUBECONFIG_PATH=$5\nfi\n\nmain\n"
	c.Header("Content-Disposition", "attachment; filename="+"\"create-kubeconfig-for-elkeid-cwpp.sh\"")
	c.Data(http.StatusOK, "application/octet-stream", []byte(policy))
}
