package midware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpCounter = initPrometheusHttpCounter()
)

func initPrometheusHttpCounter() *prometheus.CounterVec {
	prometheusOpts := prometheus.CounterOpts{
		Name: "elkeid_sd_http_api",
		Help: "Elkeid Service Discovery http api counter",
	}
	httpCounter := prometheus.NewCounterVec(prometheusOpts, []string{"path", "code"})
	prometheus.MustRegister(httpCounter)
	return httpCounter
}

func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		httpCounter.WithLabelValues(c.FullPath(), fmt.Sprintf("%d", c.Writer.Status())).Inc()
	}
}
