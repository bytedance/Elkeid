package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	RecvCounter           = initPrometheusGrpcReceiveCounter()
	SendCounter           = initPrometheusGrpcSendCounter()
	OutputDataTypeCounter = initPrometheusOutputDataTypeCounter()
	OutputAgentIDCounter  = initPrometheusOutputAgentIDCounter()
)

var AgentGauge = map[string]*prometheus.GaugeVec{
	"cpu":         initPrometheusAgentCpuGauge(),
	"rss":         initPrometheusAgentRssGauge(),
	"du":          initPrometheusAgentDuGauge(),
	"read_speed":  initPrometheusAgentReadSpeedGauge(),
	"write_speed": initPrometheusAgentWriteSpeedGauge(),
	"tx_speed":    initPrometheusAgentTxSpeedGauge(),
	"rx_speed":    initPrometheusAgentRxSpeedGauge(),
	"tx_tps":      initPrometheusAgentTxTpsGauge(),
	"rx_tpx":      initPrometheusAgentRxTpsGauge(),
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

func initPrometheusOutputDataTypeCounter() *prometheus.CounterVec {
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

func initPrometheusAgentCpuGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_cpu",
		Help: "Elkeid AC agent cpu",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
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
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentRxSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rx_speed",
		Help: "Elkeid AC agent rx speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"account_id", "agent_id", "name"})
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

func ReleaseAgentHeartbeatMetrics(accountID, agentID, pluginName string) {
	for _, v := range AgentGauge {
		_ = v.Delete(prometheus.Labels{"account_id": accountID, "agent_id": agentID, "name": pluginName})
	}
}

func UpdateFromAgentHeartBeat(accountID, agentID, name string, detail map[string]interface{}) {
	if detail == nil {
		return
	}
	for k, v := range AgentGauge {
		if cpu, ok := detail[k]; ok {
			if fv, ok2 := cpu.(float64); ok2 {
				v.With(prometheus.Labels{"account_id": accountID, "agent_id": agentID, "name": name}).Set(fv)
			}
		}
	}
}
