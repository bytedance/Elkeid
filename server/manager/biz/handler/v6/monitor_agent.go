package v6

import (
	"context"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/internal/metrics"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"github.com/gin-gonic/gin"
	"strconv"
	"strings"
)

func parseMonitorMetricsQuery(c *gin.Context) (start, end int64, period int, ret bool) {
	startTimeStr, ok := c.GetQuery("StartTime")
	if !ok {
		CreateResponse(c, common.ParamInvalidErrorCode, errors.New("StartTime is null").Error())
		return
	}
	startTime, err := strconv.ParseInt(startTimeStr, 10, 64)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, fmt.Errorf("StartTime parse error by %w", err).Error())
		return
	} else {
		start = startTime
	}

	endTimeStr, ok := c.GetQuery("EndTime")
	if !ok {
		CreateResponse(c, common.ParamInvalidErrorCode, errors.New("EndTime is null").Error())
		return
	}
	endTime, err := strconv.ParseInt(endTimeStr, 10, 64)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, fmt.Errorf("EndTime parse error by %w", err).Error())
		return
	} else {
		end = endTime
	}

	periodStr, ok := c.GetQuery("Period")
	if !ok {
		CreateResponse(c, common.ParamInvalidErrorCode, errors.New("PeriodParam is null").Error())
		return
	}
	periodInt, err := strconv.Atoi(periodStr)
	if err != nil {
		CreateResponse(c, common.ParamInvalidErrorCode, fmt.Errorf("PeriodParam parse error by %w", err).Error())
		return
	} else {
		period = periodInt
	}

	ret = true
	return
}

func parseAgentMetricsQuery(c *gin.Context) (agentID string, start, end int64, period int, ret bool) {
	ret = false
	agentIDStr, ok := c.GetQuery("AgentID")
	if !ok || strings.TrimSpace(agentIDStr) == "" {
		CreateResponse(c, common.ParamInvalidErrorCode, errors.New("AgentID is null"))
		return
	} else {
		agentID = agentIDStr
	}

	start, end, period, ret = parseMonitorMetricsQuery(c)
	return
}

func metricsForAgentHandler(templateItems []monitor.PromQueryItem) func(c *gin.Context) {
	return func(c *gin.Context) {
		agentID, start, end, period, ok := parseAgentMetricsQuery(c)
		if !ok {
			return
		}

		items := make([]monitor.PromQueryItem, 0)
		for _, item := range templateItems {
			items = append(items, monitor.PromQueryItem{
				Name:    item.Name,
				Metrics: fmt.Sprintf(item.Metrics, agentID),
			})
		}
		data, err := monitor.PromCli.SearchMetrics(context.Background(), items, start, end, period)
		if err != nil {
			CreateResponse(c, common.UnknownErrorCode, fmt.Errorf("monitor.PromClient query exec error by %w", err))
			return
		}
		CreateResponse(c, common.SuccessCode, data)
	}
}

func MetricsForAgentCpu() func(c *gin.Context) {
	return metricsForAgentHandler([]monitor.PromQueryItem{
		{Name: "cpu", Metrics: metrics.AgentCpuMetrics},
	})
}

func MetricsForAgentMemory() func(c *gin.Context) {
	return metricsForAgentHandler([]monitor.PromQueryItem{
		{Name: "memory", Metrics: metrics.AgentMemoryMetrics},
	})
}

func MetricsForAgentDisk() func(c *gin.Context) {
	return metricsForAgentHandler([]monitor.PromQueryItem{
		{Name: "read", Metrics: metrics.AgentDiskReadMetrics},
		{Name: "write", Metrics: metrics.AgentDiskWriteMetrics},
	})
}

func MetricsForAgentDiskUsage() func(c *gin.Context) {
	return metricsForAgentHandler([]monitor.PromQueryItem{
		{Name: "disk", Metrics: metrics.AgentDiskMetrics},
	})
}

func MetricsForAgentNetwork() func(c *gin.Context) {
	return metricsForAgentHandler([]monitor.PromQueryItem{
		{Name: "upload", Metrics: metrics.AgentNetUploadMetrics},
		{Name: "download", Metrics: metrics.AgentNetDownloadMetrics},
	})
}
