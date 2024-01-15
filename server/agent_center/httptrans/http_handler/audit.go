package http_handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/gin-gonic/gin"
	"github.com/levigross/grequests"
	"k8s.io/apiserver/pkg/apis/audit/v1"
	"sync"
	"time"
)

const (
	AuditEventDataType = "9003"
	kubeClusterIDUrl   = "http://%s/api/v6/kube/inner/cluster/list"
)

type Res struct {
	Code    int      `json:"code"`
	Message string   `json:"msg"`
	Data    []string `json:"data"`
}

// AuditEvent
type AuditEvent struct {
	ClusterID string    `json:"cluster_id"` // 集群 uuid，来自客户端证书中的 Subject CN（客户集群 uuid 及其证书由 console 生成和签发）
	Event     *v1.Event `json:"event"`      // k8s Event

	// 以下字段为 AgentCenter 追加的字段
	DataType string `json:"data_type"`
}

type AuditLogWriter struct {
	queue chan *AuditEvent
}

func (w *AuditLogWriter) Init() {
	w.queue = make(chan *AuditEvent, 4096*256)
}

func (w *AuditLogWriter) Run() {
	ylog.Infof("AuditLogWriter", "Run")
	for {
		select {
		case tmp := <-w.queue:
			common.KafkaRawDataProducer.SendJsonWithKey(tmp.ClusterID, tmp)
		}
	}
}

func (w *AuditLogWriter) Add(v *AuditEvent) {
	//logs.Infof("AuditLogWriter_Add ClusterID %s, Event: %#v", v.ClusterID, v.Event)
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("AuditLogWriter", "channel is full len %d", len(w.queue))
	}
}

var (
	auditLogWriter       AuditLogWriter
	clusterMap           *map[string]bool
	clusterRunningMap    map[string]int64
	clusterRunningLocker sync.RWMutex
)

//func init() {
//	auditLogWriter.Init()
//	go auditLogWriter.Run()
//
//	clusterMap = &map[string]bool{}
//	ls, err := getClusterIDList()
//	if err != nil {
//		ylog.Errorf("Audit_getClusterIDList", " %s", err.Error())
//	} else {
//		clsMap := map[string]bool{}
//		for _, v := range ls {
//			clsMap[v] = true
//		}
//		clusterMap = &clsMap
//	}
//
//	go func() {
//		for {
//			time.Sleep(time.Minute)
//			ls, err := getClusterIDList()
//			if err != nil {
//				ylog.Errorf("Audit_getClusterIDList", " %s", err.Error())
//			} else {
//				clsMap := map[string]bool{}
//				for _, v := range ls {
//					clsMap[v] = true
//				}
//				clusterMap = &clsMap
//			}
//		}
//	}()
//
//	clusterRunningMap = make(map[string]int64, 0)
//}

func RDAudit(c *gin.Context) {
	//cluster := c.Param("cluster")
	if len(c.Request.TLS.PeerCertificates) == 0 {
		ylog.Errorf("RDAudit", "get Subject CommonName failed")
		CreateResponse(c, UnknownErrorCode, "get Subject CommonName failed")
		return
	}

	cluster := c.Request.TLS.PeerCertificates[0].Subject.CommonName
	if _, ok := (*clusterMap)[cluster]; !ok {
		ylog.Errorf("RDAudit cluster uuid %s is not found", cluster)
		CreateResponse(c, UnknownErrorCode, "cluster uuid is not found")
		return
	}

	//设置为存活
	clusterRunningLocker.Lock()
	clusterRunningMap[cluster] = time.Now().Unix()
	clusterRunningLocker.Unlock()

	eventList := &v1.EventList{}
	err := c.BindJSON(eventList)
	if err != nil {
		ylog.Errorf("RDAudit cluster uuid %s, ParamInvalid %s", cluster, err.Error())
		CreateResponse(c, ParamInvalidErrorCode, err.Error())
		return
	}

	for i, _ := range eventList.Items {
		item := &AuditEvent{}
		item.DataType = AuditEventDataType
		item.ClusterID = cluster
		item.Event = &eventList.Items[i]

		auditLogWriter.Add(item)
	}

	CreateResponse(c, SuccessCode, "ok")
}

func getClusterIDList() ([]string, error) {
	resp, err := grequests.Get(fmt.Sprintf(kubeClusterIDUrl, common.GetRandomManageAddr()), &grequests.RequestOptions{
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	if !resp.Ok {
		return nil, errors.New("status code is not ok")
	}
	var response Res
	err = json.Unmarshal(resp.Bytes(), &response)
	if err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, errors.New("response code is not 0")
	}
	return response.Data, nil
}

func ClusterList(c *gin.Context) {
	arr := make([]string, 0, len(clusterRunningMap))
	nowTime := time.Now().Add(-2 * time.Minute).Unix()

	clusterRunningLocker.RLock()
	for k, v := range clusterRunningMap {
		if v > nowTime {
			arr = append(arr, k)
		}
	}
	clusterRunningLocker.RUnlock()

	CreateResponse(c, SuccessCode, arr)
}
