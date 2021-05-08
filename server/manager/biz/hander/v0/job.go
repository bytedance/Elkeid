package v0

import (
	"github.com/bytedance/Elkeid/server/manager/distribute/job"
	"github.com/gin-gonic/gin"
	"net/http"
)

type NewInfo struct {
	Name    string `json:"name"`
	ConNum  int    `json:"con_num"`
	Timeout int    `json:"timeout"`
}

func NewJob(c *gin.Context) {
	ni := NewInfo{}
	if err := c.BindJSON(&ni); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "post data error"})
		return
	}
	jobId, err := job.NewJob(ni.Name, ni.ConNum, ni.Timeout)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": jobId})
	return
}

func Distribute(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
	return
}

type StopInfo struct {
	Id string `json:"id"`
}

func Stop(c *gin.Context) {
	si := StopInfo{}
	if err := c.BindJSON(&si); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "post data error"})
		return
	}
	job.StopJob(si.Id)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
	return
}

func Sync(c *gin.Context) {
	ti := job.TransInfo{}
	if err := c.BindJSON(&ti); err != nil {
		//fmt.Printf("sync api bind error: %s\n", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"msg": "post data error"})
		return
	}
	//fmt.Printf("sync api params: %v\n", ti)
	job.SyncRecv(ti)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
	return
}

func Stat(c *gin.Context) {
	id := c.Query("id")
	statMap := job.GetStat(id)
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": statMap})
	return
}

func Result(c *gin.Context) {
	id := c.Query("id")
	r := job.GetResult(id)
	c.JSON(http.StatusOK, gin.H{"msg": "ok", "data": r})
	return
}
