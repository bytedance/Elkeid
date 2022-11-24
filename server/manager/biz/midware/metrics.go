package midware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

var apiCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "elkeid_manager_http_api_qps_counter",
	Help: "Elkeid Manager Http API QPS",
}, []string{"handle", "source", "code"})

var apiHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: "elkeid_manager_http_api_histogram",
	Help: "Elkeid Manager Http API Histogram",
}, []string{"handle", "source", "code"})

var initOnce = &sync.Once{}

func Metrics() gin.HandlerFunc {
	initOnce.Do(func() {
		prometheus.MustRegister(apiCounter)
		prometheus.MustRegister(apiHistogram)
	})
	return func(c *gin.Context) {
		begin := time.Now()

		source := c.RemoteIP()
		handle := c.HandlerName()
		c.Next()
		code := fmt.Sprint(c.Writer.Status())
		apiCounter.With(prometheus.Labels{"handle": handle, "source": source, "code": code}).Add(float64(1))
		apiHistogram.With(prometheus.Labels{"handle": handle, "source": source, "code": code}).Observe(float64(time.Since(begin)))
		return
	}
}
