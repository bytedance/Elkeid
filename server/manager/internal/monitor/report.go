package monitor

import (
	"context"
	"github.com/levigross/grequests"
	"log"
	"net/http"
	"time"
)

type Component struct {
	Instances []string `yaml:"instances"`
}

var basicMessage BasicMessage

func InitReport() {
	if !Config.AcceptInformationCollected && Config.Report.EnableReport {
		return
	}
	basicMessage.Email = Config.Report.Email
	basicMessage.Uid = Config.Report.Uid
	basicMessage.ElkeidupVersion = Config.Report.ElkeidupVersion
	basicMessage.DeployAt = Config.Report.DeployAt
	go func() {
		reportHeartbeat()
		for range time.Tick(time.Minute * 10) {
			reportHeartbeat()
		}
	}()
}

type BasicMessage struct {
	Uid             string    `json:"uid"`
	Email           string    `json:"email"`
	ElkeidupVersion string    `json:"elkeidup_version"`
	DeployAt        time.Time `json:"deploy_at"`
}

type DailyReportMessage struct {
	BasicMessage

	ComponentVersions map[string][]BuildVersion `json:"component_versions"`

	Metrics map[string]interface{} `json:"metrics"`
}

type queryItem struct {
	Query string `json:"query"`
	Value string `json:"value"`
}

var heartbeatDefaultQuery = map[string]queryItem{
	"agent_count":        {Query: "sum(elkeid_ac_grpc_conn_count)", Value: "$.data.result[0].value.[1]"},
	"ac_receive_qps_30m": {Query: "sum(rate(elkeid_ac_grpc_recv_qps[30m]))", Value: "$.data.result[0].value.[1]"},
	"ac_send_qps_30m":    {Query: "sum(rate(elkeid_ac_grpc_send_qps[30m]))", Value: "$.data.result[0].value.[1]"},
	"hub_input_qps_30m":  {Query: "sum(rate(elkeid_hub_stream_counter{type='input'}[30m]))", Value: "$.data.result[0].value.[1]"},
	"redis_qps_30m":      {Query: "sum(rate(redis_commands_processed_total[30m]))", Value: "$.data.result[0].value.[1]"},
	"redis_memory_usage": {Query: "(redis_memory_used_bytes/redis_memory_max_bytes)", Value: "$.data.result[0].value.[1]"},
	"kafka_in_qps_30m":   {Query: "sum(rate(kafka_topic_partition_current_offset[30m]))", Value: "$.data.result[0].value.[1]"},
	"kafka_out_qps_30m":  {Query: "sum(rate(kafka_consumergroup_current_offset[30m]))", Value: "$.data.result[0].value.[1]"},
	"mongodb_qps_30m":    {Query: "sum(rate(mongodb_op_counters_total{type!=\"command\"}[30m]))", Value: "$.data.result[0].value.[1]"},
}

type HeartbeatMessage struct {
	BasicMessage
	Metrics map[string]interface{} `json:"metrics"`
}

func reportHeartbeat() {
	reportConfig := Config.Report
	log.Println("Start Heartbeat report")
	ctx := context.Background()
	message := HeartbeatMessage{
		BasicMessage: basicMessage,
	}

	message.Metrics = make(map[string]interface{})
	for k, v := range heartbeatDefaultQuery {
		ret, err := PromCli.QueryWithJsonPath(ctx, v.Query, v.Value)
		if err != nil {
			message.Metrics[k] = err.Error()
		} else {
			message.Metrics[k] = ret
		}
	}

	post(reportConfig.HeartbeatUrl, message)
}

func post(url string, content interface{}) {
	opts := grequests.RequestOptions{
		JSON: content,
	}
	resp, err := grequests.Post(url, &opts)
	if err != nil {
		log.Println("post to " + url + " error: " + err.Error())
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Println("post to "+url+" failed, resp code: ", resp.StatusCode)
	}
}
