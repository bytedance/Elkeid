package metrics

import (
	m "code.byted.org/gopkg/metrics/v4"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	RecvCounter          = initPrometheusGrpcReceiveCounter()
	SendCounter          = initPrometheusGrpcSendCounter()
	OutputAgentIDCounter = initPrometheusOutputAgentIDCounter()
)

var (
	RecvCounterMetric          = initMetricsGrpcReceiveCounter()
	SendCounterMetric          = initMetricsGrpcSendCounter()
	OutputAgentIDCounterMetric = initMetricsOutputAgentIDCounter()
)

var AgentGauge = map[string]*prometheus.GaugeVec{
	common.MetricsTypePluginCpu:          initPrometheusAgentCpuGauge(),
	common.MetricsTypePluginRss:          initPrometheusAgentRssGauge(),
	common.MetricsTypePluginDu:           initPrometheusAgentDuGauge(),
	common.MetricsTypePluginReadSpeed:    initPrometheusAgentReadSpeedGauge(),
	common.MetricsTypePluginWriteSpeed:   initPrometheusAgentWriteSpeedGauge(),
	common.MetricsTypePluginAgentTxSpeed: initPrometheusAgentTxSpeedGauge(),
	common.MetricsTypePluginAgentRxSpeed: initPrometheusAgentRxSpeedGauge(),
	common.MetricsTypePluginTxTps:        initPrometheusAgentTxTpsGauge(),
	common.MetricsTypePluginRxTps:        initPrometheusAgentRxTpsGauge(),
	common.MetricsTypePluginNfd:          initPrometheusAgentNfdGauge(),
	common.MetricsTypeAgentDiscardCnt:    initPrometheusAgentDiscardCntGauge(),
	common.MetricsTypeAgentDiskFreeBytes: initPrometheusAgentDiskFreeBytesGauge(),
}

var AgentGaugeMetricMap = map[string]m.Metric{
	common.MetricsTypePluginCpu:          initMetricsAgentCpuGauge(),
	common.MetricsTypePluginRss:          initMetricsAgentRssGauge(),
	common.MetricsTypePluginDu:           initMetricsAgentDuGauge(),
	common.MetricsTypePluginReadSpeed:    initMetricsAgentReadSpeedGauge(),
	common.MetricsTypePluginWriteSpeed:   initMetricsAgentWriteSpeedGauge(),
	common.MetricsTypePluginAgentTxSpeed: initMetricsAgentTxSpeedGauge(),
	common.MetricsTypePluginAgentRxSpeed: initMetricsAgentRxSpeedGauge(),
	common.MetricsTypePluginTxTps:        initMetricsAgentTxTpsGauge(),
	common.MetricsTypePluginRxTps:        initMetricsAgentRxTpsGauge(),
	common.MetricsTypePluginNfd:          initMetricsAgentNfdGauge(),
	common.MetricsTypeAgentDiscardCnt:    initMetricsAgentDiscardCntGauge(),
	common.MetricsTypeAgentDiskFreeBytes: initMetricsAgentDiskFreeBytesGauge(),
}

var Client m.Client

func InitMetrics() {
	var err error
	Client, err = m.NewClient("elkeid.ac")
	if err != nil {
		ylog.Infof("initMetrics", "init metrics client error:%s", err.Error())
	}
}

func initPrometheusGrpcReceiveCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_recv_qps",
		Help: "Elkeid AC grpc receive qps",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"account_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsGrpcReceiveCounter() m.Metric {
	metric, err := Client.NewMetricWithOps("grpc.recv.qps", []string{"account_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsGrpcReceiveCounter error:%s", err.Error())
	}
	return metric
}

func initPrometheusGrpcSendCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_send_qps",
		Help: "Elkeid AC grpc send qps",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"account_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsGrpcSendCounter() m.Metric {
	metric, err := Client.NewMetricWithOps("grpc.send.qps", []string{"account_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsGrpcSendCounter error:%s", err.Error())
	}
	return metric
}

func initPrometheusOutputDataTypeCounter() *prometheus.CounterVec { // 取消上报
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_output_data_type_count",
		Help: "Elkeid AC output data count for data_type",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"account_id", "data_type"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusOutputAgentIDCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_output_count",
		Help: "Elkeid AC output data count for agent_id",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsOutputAgentIDCounter() m.Metric {
	metric, err := Client.NewMetricWithOps("output", []string{"account_id", "agent_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsOutputAgentIDCounter error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentCpuGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_cpu",
		Help: "Elkeid AC agent cpu",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name", "pversion"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentCpuGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.cpu", []string{"account_id", "agent_id", "name", "pversion"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentCpuGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentRssGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rss",
		Help: "Elkeid AC agent rss",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentRssGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.rss", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentRssGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentDuGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_du",
		Help: "Elkeid AC agent du",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentDuGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.du", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentDuGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentReadSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_read_speed",
		Help: "Elkeid AC agent read speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentReadSpeedGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.read.speed", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentReadSpeedGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentWriteSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_write_speed",
		Help: "Elkeid AC agent write speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentWriteSpeedGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.write.speed", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentWriteSpeedGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentTxSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_tx_speed",
		Help: "Elkeid AC agent tx speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentTxSpeedGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.tx.speed", []string{"account_id", "agent_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentTxSpeedGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentRxSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rx_speed",
		Help: "Elkeid AC agent rx speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentRxSpeedGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.rx.speed", []string{"account_id", "agent_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentRxSpeedGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentTxTpsGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_tx_tps",
		Help: "Elkeid AC agent tx tps",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentTxTpsGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.tx.tps", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentTxTpsGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentRxTpsGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rx_tps",
		Help: "Elkeid AC agent rx tps",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentRxTpsGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.rx.tps", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentRxTpsGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentNfdGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_nfd",
		Help: "Elkeid AC agent nfd",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentNfdGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.nfd", []string{"account_id", "agent_id", "name"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentNfdGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentDiscardCntGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_discard_cnt",
		Help: "Elkeid AC agent discard cnt",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentDiscardCntGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("agent.discard.cnt", []string{"account_id", "agent_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentDiscardCntGauge error:%s", err.Error())
	}
	return metric
}

func initPrometheusAgentDiskFreeBytesGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_disk_free_bytes",
		Help: "Elkeid AC agent disk free bytes",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initMetricsAgentDiskFreeBytesGauge() m.Metric {
	metric, err := Client.NewMetricWithOps("disk.free.bytes", []string{"account_id", "agent_id"})
	if err != nil {
		ylog.Infof("initMetrics", "initMetricsAgentDiskFreeBytesGauge error:%s", err.Error())
	}
	return metric
}

func ReleaseAgentHeartbeatMetrics(accountID, agentID, pluginName string, pversion string) {
	for k, v := range AgentGauge {
		switch k {
		case common.MetricsTypePluginCpu:
			_ = v.Delete(prometheus.Labels{"account_id": accountID, "agent_id": agentID, "name": pluginName, "pversion": pversion})
		case common.MetricsTypePluginAgentRxSpeed,
			common.MetricsTypePluginAgentTxSpeed,
			common.MetricsTypeAgentDiscardCnt,
			common.MetricsTypeAgentDiskFreeBytes:
			_ = v.Delete(prometheus.Labels{"account_id": accountID, "agent_id": agentID})
		default:
			_ = v.Delete(prometheus.Labels{"account_id": accountID, "agent_id": agentID, "name": pluginName})
		}
	}
}

func UpdateFromAgentHeartBeat(accountID, agentID, name string, detail map[string]interface{}) {
	if detail == nil {
		return
	}
	for k, v := range AgentGauge {
		if t, ok := detail[k]; ok {
			if fv, ok2 := t.(float64); ok2 {
				switch k {
				case common.MetricsTypePluginCpu: // plugin cpu指标补充上报plugin version
					pversion := ""
					key := "pversion"
					if name == "agent" {
						key = "version"
					}
					if t1, ok3 := detail[key]; ok3 {
						if t2, ok4 := t1.(string); ok4 {
							pversion = t2
						}
					}
					v.With(prometheus.Labels{"account_id": accountID, "agent_id": agentID, "name": name, "pversion": pversion}).Set(fv)
				case common.MetricsTypePluginAgentRxSpeed,
					common.MetricsTypePluginAgentTxSpeed,
					common.MetricsTypeAgentDiscardCnt,
					common.MetricsTypeAgentDiskFreeBytes: // 只上报agent指标
					if name != "agent" {
						continue
					} else {
						v.With(prometheus.Labels{"account_id": accountID, "agent_id": agentID}).Set(fv)
					}
				default:
					v.With(prometheus.Labels{"account_id": accountID, "agent_id": agentID, "name": name}).Set(fv)
				}
			}
		}
	}
	for k, v := range AgentGaugeMetricMap {
		if t, ok := detail[k]; ok {
			if fv, ok2 := t.(float64); ok2 {
				switch k {
				case common.MetricsTypePluginCpu: // plugin cpu指标补充上报plugin version
					pversion := ""
					key := "pversion"
					if name == "agent" {
						key = "version"
					}
					if t1, ok3 := detail[key]; ok3 {
						if t2, ok4 := t1.(string); ok4 {
							pversion = t2
						}
					}
					v.WithTags(
						m.T{Name: "account_id", Value: accountID},
						m.T{Name: "agent_id", Value: agentID},
						m.T{Name: "name", Value: name},
						m.T{Name: "pversion", Value: pversion},
					).Emit(m.Storef(fv))
				case common.MetricsTypePluginAgentRxSpeed,
					common.MetricsTypePluginAgentTxSpeed,
					common.MetricsTypeAgentDiscardCnt,
					common.MetricsTypeAgentDiskFreeBytes: // 只上报agent指标
					if name != "agent" {
						continue
					} else {
						v.WithTags(
							m.T{Name: "account_id", Value: accountID},
							m.T{Name: "agent_id", Value: agentID},
						).Emit(m.Storef(fv))
					}
				default:
					v.WithTags(
						m.T{Name: "account_id", Value: accountID},
						m.T{Name: "agent_id", Value: agentID},
						m.T{Name: "name", Value: name},
					).Emit(m.Storef(fv))
				}
			}
		}
	}
}
