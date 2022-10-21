package grpc_handler

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	recvCounter           = initPrometheusGrpcReceiveCounter()
	sendCounter           = initPrometheusGrpcSendCounter()
	outputDataTypeCounter = initPrometheusOutputDataTypeCounter()
	outputAgentIDCounter  = initPrometheusOutputAgentIDCounter()
)

var agentGauge = map[string]*prometheus.GaugeVec{
	"cpu":         initPrometheusAgentCpuGauge(),
	"rss":         initPrometheusAgentRssGauge(),
	"du":          initPrometheusAgentDuGauge(),
	"read_speed":  initPrometheusAgentReadSpeedGauge(),
	"write_speed": initPrometheusAgentWriteSpeedGauge(),
	"tx_speed":    initPrometheusAgentTxSpeedGauge(),
	"rx_speed":    initPrometheusAgentRxSpeedGauge(),
}

func initPrometheusGrpcConnGauge() {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_grpc_conn_count",
		Help: "Elkeid AC grpc connection count",
	}
	gauge := prometheus.NewGaugeFunc(prometheusOpts, func() float64 {
		return float64(GlobalGRPCPool.GetCount())
	})
	prometheus.MustRegister(gauge)
}

func initPrometheusGrpcReceiveCounter() prometheus.Counter {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_recv_qps",
		Help: "Elkeid AC grpc receive qps",
	}
	counter := prometheus.NewCounter(prometheusOpts)
	prometheus.MustRegister(counter)
	return counter
}

func initPrometheusGrpcSendCounter() prometheus.Counter {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_send_qps",
		Help: "Elkeid AC grpc send qps",
	}
	counter := prometheus.NewCounter(prometheusOpts)
	prometheus.MustRegister(counter)
	return counter
}

func initPrometheusOutputDataTypeCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_output_data_type_count",
		Help: "Elkeid AC output data count for data_type",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"data_type"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusOutputAgentIDCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_output_count",
		Help: "Elkeid AC output data count for agent_id",
	}
	vec := prometheus.NewCounterVec(prometheusOpts, []string{"agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentCpuGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_cpu",
		Help: "Elkeid AC agent cpu",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentRssGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rss",
		Help: "Elkeid AC agent rss",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentDuGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_du",
		Help: "Elkeid AC agent du",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentReadSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_read_speed",
		Help: "Elkeid AC agent read speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentWriteSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_write_speed",
		Help: "Elkeid AC agent write speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentTxSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_tx_speed",
		Help: "Elkeid AC agent tx speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusAgentRxSpeedGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_agent_rx_speed",
		Help: "Elkeid AC agent rx speed",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func releaseAgentHeartbeatMetrics(agentID string) {
	// tmp remove all gauge for v1.9.1
	for _, v := range agentGauge {
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "agent"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "driver"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "rasp"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "etrace"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "baseline"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "collector"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "journal_watcher"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "scanner"})
		_ = v.Delete(prometheus.Labels{"agent_id": agentID, "name": "scanner_clamav"})
	}
}

func init() {
	initPrometheusGrpcConnGauge()
}
