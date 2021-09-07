package http_handler

import (
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/apis/audit"
)

const AuditEventDataType = "1050"

// AuditEvent
type AuditEvent struct {
	Cluster  string `json:"cluster"`
	DataType string `json:"data_type"`
	metav1.TypeMeta
	metav1.ListMeta
	audit.Event
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
			common.KafkaProducer.SendWithKey(string(tmp.AuditID), tmp)
		}
	}
}

func (w *AuditLogWriter) Add(v *AuditEvent) {
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("AuditLogWriter", "channel is full len %d", len(w.queue))
	}
}

var auditLogWriter AuditLogWriter

func init() {
	auditLogWriter.Init()
	go auditLogWriter.Run()
}

func RDAudit(c *gin.Context) {
	cluster := c.Param("cluster")

	eventList := &audit.EventList{}
	err := c.BindJSON(eventList)
	if err != nil {
		CreateResponse(c, ParamInvalidErrorCode, err.Error())
		return
	}

	for _, event := range eventList.Items {
		item := &AuditEvent{}
		item.DataType = AuditEventDataType
		item.Cluster = cluster
		item.TypeMeta = eventList.TypeMeta
		item.ListMeta = eventList.ListMeta
		item.Event = event

		auditLogWriter.Add(item)
	}

	CreateResponse(c, SuccessCode, "ok")
}
