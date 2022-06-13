package es

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/olivere/elastic/v7"
	"sync"
	"time"
)

const (
	maxCachedAgentErrLogs = 1000
	cachedTimeInterval    = time.Second * 15
)

type RecordLog struct {
	AgentID   string            `json:"agent_id"`
	Content   map[string]string `json:"content"`
	Timestamp time.Time         `json:"timestamp"`
}

var (
	esCli      *elastic.Client
	mutex      = &sync.Mutex{}
	cachedLogs = make([]*RecordLog, 0)
)

func initEsClient() error {
	var err error

	ops := make([]elastic.ClientOptionFunc, 0)
	ops = append(ops, elastic.SetURL(common.EsAddress))
	ops = append(ops, elastic.SetSniff(true))
	if common.EsAuthEnable {
		ops = append(ops, elastic.SetBasicAuth(common.EsUser, common.EsPassword))
	}
	esCli, err = elastic.NewClient(ops...)
	return err
}

func Run() {
	if common.EsEnable {
		for {
			err := initEsClient()
			if err != nil {
				ylog.Errorf("EsInit", "error: %s", err.Error())
				time.Sleep(time.Second * 3)
			} else {
				ylog.Infof("EsInit", "success at %s", common.EsAddress)
				break
			}
		}

		for range time.Tick(cachedTimeInterval) {
			sendLogToEs()
		}

	}
}

func sendLogToEs() {
	mutex.Lock()
	if len(cachedLogs) == 0 {
		ylog.Infof("EsClient", "err log count is zero, skip")
		mutex.Unlock()
		return
	}

	bulkRequest := esCli.Bulk()
	index := fmt.Sprintf("agent_err_log_%d%02d%02d", time.Now().Year(), time.Now().Month(), time.Now().Day())
	ctx, cancel := context.WithTimeout(context.Background(), cachedTimeInterval)
	defer cancel()

	for i := 0; i < len(cachedLogs); i++ {
		req := elastic.NewBulkIndexRequest().OpType("index").Index(index).Doc(*(cachedLogs[i]))
		bulkRequest = bulkRequest.Add(req)
	}

	docCount := len(cachedLogs)

	// not lock when post data to es
	cachedLogs = cachedLogs[:0]
	mutex.Unlock()

	bulkResponse, err := bulkRequest.Do(ctx)
	if err != nil {
		ylog.Errorf("EsClient", "bulk request do error: %s", err.Error())
		return
	}
	if bulkResponse != nil {
		if bulkResponse.Errors {
			for _, item := range bulkResponse.Items {
				for k, v := range item {
					if v != nil && (*v).Error != nil {
						ylog.Errorf("EsClient", "bulk response (%s) error: %s", k, (*v).Error.Reason)
					}
				}
			}

		}
	}
	ylog.Infof("EsClient", "write %d logs to es %s completed", docCount, index)
	return
}

func CollectLog(agentID string, content map[string]string) {
	if esCli == nil {
		ylog.Warnf("EsClient", "es client is null, not send error log to es")
		return
	}
	mutex.Lock()
	defer mutex.Unlock()

	if len(cachedLogs) >= maxCachedAgentErrLogs {
		ylog.Warnf("EsClient", "cached logs full, not send error log to es")
		return
	} else {
		cachedLogs = append(cachedLogs, &RecordLog{
			AgentID:   agentID,
			Content:   content,
			Timestamp: time.Now(),
		})
	}
}
