package metrics

import (
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	RecvCounter          = initPrometheusGrpcReceiveCounter()
	SendCounter          = initPrometheusGrpcSendCounter()
	OutputAgentIDCounter = initPrometheusOutputAgentIDCounter()
	StartCounter         = initPrometheusAgentStartCounter()
	ExitGauge            = initPrometheusAgentExitGauge()
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

func initPrometheusGrpcReceiveCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_recv_qps",
		Help: "Elkeid AC grpc receive qps",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"account_id"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentStartCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_agent_start_qps",
		Help: "Elkeid AC agent start qps",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"account_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentExitGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_exit",
		Help: "Elkeid AC agent exit",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name", "exit_code"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentRssGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rss",
		Help: "Elkeid AC agent rss",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentReadSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_read_speed",
		Help: "Elkeid AC agent read speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentTxSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_tx_speed",
		Help: "Elkeid AC agent tx speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentTxTpsGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_tx_tps",
		Help: "Elkeid AC agent tx tps",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentNfdGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_nfd",
		Help: "Elkeid AC agent nfd",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
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

func initPrometheusAgentDiskFreeBytesGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_disk_free_bytes",
		Help: "Elkeid AC agent disk free bytes",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id"})
	prometheus.MustRegister(vec)
	return vec
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
}
