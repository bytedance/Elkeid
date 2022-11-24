package v6

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/internal/metrics"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"github.com/gin-gonic/gin"
)

func MonitorHostStatistics(c *gin.Context) {
	metrics.UpdateHostUsage()
	type hostStatistics struct {
		Total           int    `json:"total"`
		HighestLoadID   string `json:"highest_load_id"`
		HighestLoadIP   string `json:"highest_load_ip"`
		HighestLoadName string `json:"highest_load_name"`
	}

	statistics := hostStatistics{
		Total:           len(metrics.HostUsageList),
		HighestLoadID:   "n010-227-007-024",
		HighestLoadIP:   "10.227.7.24",
		HighestLoadName: "n227-007-024",
	}

	load := float64(0)
	for _, h := range metrics.HostUsageList {
		if load < h.LoadScore {
			statistics.HighestLoadID = h.ID
			statistics.HighestLoadIP = h.HostIP
			statistics.HighestLoadName = h.HostName
			load = h.LoadScore
		}
	}
	CreateResponse(c, common.SuccessCode, statistics)
}

func MonitorDescribeHosts(c *gin.Context) {
	metrics.UpdateHostUsage()
	CreateResponse(c, common.SuccessCode, metrics.HostUsageList)
}

func MonitorHostAllMetrics(c *gin.Context) {
	start, end, period, ret := parseMonitorMetricsQuery(c)
	if !ret {
		return
	}
	var id, ip string
	var idOk, ipOk bool
	id, idOk = c.GetQuery("ID")
	if !idOk {
		ip, ipOk = c.GetQuery("HostIP")
		if !ipOk {
			common.CreateResponse(c, common.ParamInvalidErrorCode, errors.New("ip or id is nil").Error())
		}
	} else {
		for _, info := range monitor.GetAllHosts() {
			if info.ID == id {
				ip = info.IP
			}
		}
		if ip == "" {
			common.CreateResponse(c, common.ParamInvalidErrorCode, errors.New("id not exist").Error())
		}
	}
	items := make([]monitor.PromQueryItem, 0)
	items = append(items, monitor.PromQueryItem{
		Name:    "cpu",
		Metrics: fmt.Sprintf(metrics.HostCpuUsageMetrics, ip, ip),
	})
	items = append(items, monitor.PromQueryItem{
		Name:    "memory",
		Metrics: fmt.Sprintf(metrics.HostMemUsageMetrics, ip, ip),
	})
	items = append(items, monitor.PromQueryItem{
		Name:    "disk",
		Metrics: fmt.Sprintf(metrics.HostDiskUsageMetrics, ip, ip),
	})
	data, err := monitor.PromCli.SearchMetrics(context.Background(), items, start, end, period)
	if err != nil {
		CreateResponse(c, common.UnknownErrorCode, fmt.Errorf("monitor.PromClient query exec error by %w", err).Error())
		return
	}
	CreateResponse(c, common.SuccessCode, data)

}

func MonitorHostAvgMetrics(c *gin.Context) {
	start, end, period, ret := parseMonitorMetricsQuery(c)
	if !ret {
		return
	}
	items := make([]monitor.PromQueryItem, 0)
	items = append(items, monitor.PromQueryItem{
		Name:    "cpu",
		Metrics: metrics.HostCpuAvgUsageMetrics,
	})
	items = append(items, monitor.PromQueryItem{
		Name:    "memory",
		Metrics: metrics.HostMemAvgUsageMetrics,
	})
	items = append(items, monitor.PromQueryItem{
		Name:    "disk",
		Metrics: metrics.HostDiskAvgUsageMetrics,
	})
	data, err := monitor.PromCli.SearchMetrics(context.Background(), items, start, end, period)
	if err != nil {
		CreateResponse(c, common.UnknownErrorCode, fmt.Errorf("monitor.PromClient query exec error by %w", err).Error())
		return
	}
	CreateResponse(c, common.SuccessCode, data)
}

func MonitorExportHost(c *gin.Context) {
	metrics.UpdateHostUsage()
	type exportReq struct {
		IdList []string `json:"id_list"`
	}
	exportIdMap := make(map[string]bool)
	req := exportReq{}
	err := c.BindJSON(&req)
	if err == nil && len(req.IdList) != 0 {
		for _, v := range req.IdList {
			exportIdMap[v] = true
		}
	}
	exportList := make([][]string, 0)
	for _, usage := range metrics.HostUsageList {
		line := []string{
			usage.ID,
			usage.HostName,
			usage.HostIP,
			strings.Join(usage.ServiceList, "+"),
			usage.Quota,
			fmt.Sprint(usage.CpuUsage),
			fmt.Sprint(usage.MemoryUsage),
			fmt.Sprint(usage.DiskUsage),
			fmt.Sprint(usage.NetUpload),
			fmt.Sprint(usage.NetDownload),
			fmt.Sprint(usage.Detail),
		}
		if len(exportIdMap) == 0 || exportIdMap[usage.ID] {
			exportList = append(exportList, line)
		}
	}
	header := common.MongoDBDefs{
		{Key: "ID", Header: "ID"},
		{Key: "Name", Header: "Name"},
		{Key: "IP", Header: "IP"},
		{Key: "ServiceList", Header: "ServiceList"},
		{Key: "Quota", Header: "Quota"},
		{Key: "CpuUsage", Header: "CpuUsage"},
		{Key: "MemoryUsage", Header: "MemoryUsage"},
		{Key: "DiskUsage", Header: "DiskUsage"},
		{Key: "NetUpload", Header: "NetUpload"},
		{Key: "NetDownload", Header: "NetDownload"},
		{Key: "Detail", Header: "Detail"},
	}
	filename := "monitor_host_" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}
