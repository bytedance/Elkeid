package handler

import (
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

func initPrometheusRegistryList() {
	prometheusOpts := prometheus.GaugeOpts{
		Name: "elkeid_sd_registry_list",
		Help: "Elkeid Service Discovery registry list info",
	}
	listGauge := prometheus.NewGaugeVec(prometheusOpts, []string{"name"})
	prometheus.MustRegister(listGauge)
	go func() {
		for range time.Tick(time.Second * 30) {
			if EI != nil {
				ret := EI.RegistrySummary()
				for k, v := range ret {
					listGauge.WithLabelValues(k).Set(float64(v))
				}
			}
		}
	}()
}

func init() {
	initPrometheusRegistryList()
}
