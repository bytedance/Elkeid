package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func Ping(c *gin.Context) {
	r := make(map[string]interface{})
	r["host"] = CI.GetHost()
	r["members"] = CI.GetHosts()
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": r})
	return
}

func EndpointStat(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": CI.GetHosts()})
	return
}
