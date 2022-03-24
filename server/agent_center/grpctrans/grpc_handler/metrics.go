package grpc_handler

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	recvCounter = initPrometheusGrpcReceiveCount()
	sendCounter = initPrometheusGrpcSendCount()
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

func initPrometheusGrpcReceiveCount() prometheus.Counter {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_recv_qps",
		Help: "Elkeid AC grpc receive qps",
	}
	counter := prometheus.NewCounter(prometheusOpts)
	prometheus.MustRegister(counter)
	return counter
}

func initPrometheusGrpcSendCount() prometheus.Counter {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_ac_grpc_send_qps",
		Help: "Elkeid AC grpc send qps",
	}
	counter := prometheus.NewCounter(prometheusOpts)
	prometheus.MustRegister(counter)
	return counter
}

func init() {
	initPrometheusGrpcConnGauge()
}
