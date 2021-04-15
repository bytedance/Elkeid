package handler

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/service_discovery/endpoint"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

const (
	defaultFetchCount = 100
)

type RegisterInfo struct {
	Name   string                 `json:"name"`
	Ip     string                 `json:"ip"`
	Port   int                    `json:"port"`
	Weight int                    `json:"weight"`
	Extra  map[string]interface{} `json:"extra"`
}

func Register(c *gin.Context) {
	ri := RegisterInfo{
		Extra: make(map[string]interface{}),
	}
	if err := c.BindJSON(&ri); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "post data error"})
		return
	}
	EI.Register(ri.Name, ri.Ip, ri.Port, ri.Weight, ri.Extra)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
	return
}

type EvictInfo struct {
	Name string `json:"name"`
	Ip   string `json:"ip"`
	Port int    `json:"port"`
}

func Evict(c *gin.Context) {
	ei := EvictInfo{}
	if err := c.BindJSON(&ei); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "post data error"})
		return
	}
	EI.Evict(ei.Name, ei.Ip, ei.Port)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
	return
}

func Sync(c *gin.Context) {
	ti := endpoint.TransInfo{
		Data: make([]endpoint.SyncInfo, 0),
	}
	if err := c.BindJSON(&ti); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "post data error"})
		return
	}
	if err := EI.Recv(ti); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
	return
}

func Fetch(c *gin.Context) {
	var fa endpoint.FetchAlgorithm
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "no server name"})
		return
	}
	mode := c.Query("mode")
	switch mode {
	case "min":
		fa = endpoint.FetchMinN
	case "max":
		fa = endpoint.FetchMaxN
	case "rand":
		fa = endpoint.FetchRandomN
	default:
		fa = endpoint.FetchMinN
	}
	count := c.Query("count")
	n, _ := strconv.ParseInt(count, 10, 64)
	if n == 0 {
		n = 5
	}
	if n > defaultFetchCount {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "fetch count out of limit"})
		return
	}
	regs, err := EI.Fetch(name, int(n), fa)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"msg": fmt.Sprintf("fetch registry error: %s", err.Error())})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": regs})

	return
}

func RegistryDetail(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "no server name"})
		return
	}
	regs := EI.RegistryDetail(name)
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": regs})
	return
}

func RegistryList(c *gin.Context) {
	regList := EI.RegistryList()
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": regList})
}

func RegistrySummary(c *gin.Context) {
	rs := EI.RegistrySummary()
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": rs})
}
