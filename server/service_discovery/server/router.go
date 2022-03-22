package server

import (
	"github.com/bytedance/Elkeid/server/service_discovery/common"
	"github.com/bytedance/Elkeid/server/service_discovery/server/handler"
	"github.com/bytedance/Elkeid/server/service_discovery/server/midware"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

func register(r *gin.Engine) {
	r.GET("/metrics", func(c *gin.Context) {
		promhttp.Handler().ServeHTTP(c.Writer, c.Request)
	})
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	authorized := r.Group("/")
	if common.AuthEnable {
		authorized.Use(midware.AKSKAuth())
	}
	{
		authorized.POST("/registry/register", handler.Register)
		authorized.POST("/registry/evict", handler.Evict)
		authorized.POST("/registry/sync", handler.Sync)
	}

	//endpoint
	r.GET("/endpoint/ping", handler.Ping)
	r.GET("/endpoint/stat", handler.EndpointStat)

	//stat
	r.GET("/registry/summary", handler.RegistrySummary)
	r.GET("/registry/detail", handler.RegistryDetail)
	r.GET("/registry/list", handler.RegistryList)
}
