package v6

import (
	"fmt"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/internal/metrics"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/gin-gonic/gin"
)

func MonitorServiceStatus(c *gin.Context) {
	type ServiceStatusEntry struct {
		Usage  int    `json:"usage"`
		Status string `json:"status"`
	}
	type ServiceStatusResponse struct {
		AccessService  ServiceStatusEntry `json:"access_service"`
		StorageService ServiceStatusEntry `json:"storage_service"`
		ProcessService ServiceStatusEntry `json:"process_service"`
	}

	metrics.UpdateServiceStatistics()
	// mock data for internal version
	CreateResponse(c, common.SuccessCode, ServiceStatusResponse{
		AccessService: ServiceStatusEntry{
			Usage:  metrics.ServiceStatistics.AcUsage,
			Status: metrics.ServiceStatistics.AcStatus,
		},
		StorageService: ServiceStatusEntry{
			Usage:  metrics.ServiceStatistics.KafkaUsage,
			Status: metrics.ServiceStatistics.KafkaStatus,
		},
		ProcessService: ServiceStatusEntry{
			Usage:  metrics.ServiceStatistics.HubUsage,
			Status: metrics.ServiceStatistics.HubStatus,
		},
	})
}

func MonitorServiceStatistics(c *gin.Context) {
	metrics.UpdateServiceStatistics()
	// mock data for internal version
	CreateResponse(c, common.SuccessCode, metrics.ServiceStatistics)
}

func MonitorServiceList(c *gin.Context) {
	metrics.UpdateServiceList()
	// mock data for internal version
	CreateResponse(c, common.SuccessCode, gin.H{"service_list": metrics.ServiceInfoList})
}

func MonitorExportService(c *gin.Context) {
	metrics.UpdateServiceList()
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
	for _, info := range metrics.ServiceInfoList {
		line := []string{
			info.ID,
			info.Name,
			info.Description,
			info.Version,
			info.Build,
			info.CI,
			info.Commit,
			info.Quota,
			time.Unix(info.LastHeartbeat, 0).String(),
			fmt.Sprint(info.Alive),
			fmt.Sprint(info.Sum),
		}
		if len(exportIdMap) == 0 || exportIdMap[info.ID] {
			exportList = append(exportList, line)
		}
	}
	header := common.MongoDBDefs{
		{Key: "ID", Header: "ID"},
		{Key: "Name", Header: "Name"},
		{Key: "Description", Header: "Description"},
		{Key: "Version", Header: "Version"},
		{Key: "Build", Header: "Build"},
		{Key: "CI", Header: "CI"},
		{Key: "Commit", Header: "Commit"},
		{Key: "Quota", Header: "Quota"},
		{Key: "LastHeartbeat", Header: "LastHeartbeat"},
		{Key: "Alive", Header: "Alive"},
		{Key: "Sum", Header: "Sum"},
	}
	filename := "monitor_service_" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + utils.GenerateRandomString(8) + ".zip"
	common.ExportFromList(c, exportList, header, filename)
}
