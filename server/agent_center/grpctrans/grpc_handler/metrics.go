package grpc_handler

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	recvCounter           = initPrometheusGrpcReceiveCounter()
	sendCounter           = initPrometheusGrpcSendCounter()
	outputDataTypeCounter = initPrometheusOutputDataTypeCounter()
	outputAgentIDCounter  = initPrometheusOutputAgentIDCounter()

	agentCpuGauge  = initPrometheusAgentCpuGauge()
	pluginCpuGauge = initPrometheusPluginCpuGauge()
)

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
		Name: "elkeid_ac_agent_cpu_usage",
		Help: "Elkeid AC agent cpu usage",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id"})
	prometheus.MustRegister(vec)
	return vec
}

func initPrometheusPluginCpuGauge() *prometheus.GaugeVec {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_ac_plugin_cpu_usage",
		Help: "Elkeid AC agent plugin cpu usage",
	}
	vec := prometheus.NewGaugeVec(prometheusOpts, []string{"agent_id", "name"})
	prometheus.MustRegister(vec)
	return vec
}

func init() {
	initPrometheusGrpcConnGauge()
}
