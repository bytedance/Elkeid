package metrics

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"sync"
	"time"
)

var HostUsageList = make([]*BackendHostUsage, 0)
var HostUsageListLastUpdate = time.Time{}
var HostUsageListUpdateMutex = &sync.Mutex{}

type BackendHostUsage struct {
	ID          string   `json:"id"`
	HostName    string   `json:"host_name"`
	HostIP      string   `json:"host_ip"`
	ServiceList []string `json:"service_list"`
	Quota       string   `json:"quota"`
	CpuUsage    float64  `json:"cpu_usage"`
	MemoryUsage float64  `json:"memory_usage"`
	DiskUsage   float64  `json:"disk_usage"`
	NetUpload   float64  `json:"net_upload"`
	NetDownload float64  `json:"net_download"`
	Detail      string   `json:"detail"`
	Status      string   `json:"status"`

	Info      monitor.HostInfo `json:"-"`
	LoadScore float64          `json:"-"`
}

func UpdateHostUsage() {
	HostUsageListUpdateMutex.Lock()
	defer HostUsageListUpdateMutex.Unlock()
	if time.Now().Sub(HostUsageListLastUpdate) > time.Second*30 {
		defer func() {
			HostUsageListLastUpdate = time.Now()
		}()
		if len(HostUsageList) == 0 {
			HostUsageList = make([]*BackendHostUsage, 0)
			for _, info := range monitor.GetAllHosts() {
				HostUsageList = append(HostUsageList, &BackendHostUsage{Info: info})
			}
		}
		for _, usage := range HostUsageList {
			errList := usage.UpdateBackendHostUsage()
			if len(errList) != 0 {
				for _, err := range errList {
					ylog.Errorf("UpdateBackendHostUsage", err.Error())
				}
			}
		}
	}
}

func (u *BackendHostUsage) UpdateBackendHostUsage() []error {
	errorList := make([]error, 0)
	u.ID = u.Info.ID
	u.HostIP = u.Info.IP
	u.ServiceList = u.Info.Services
	u.Detail = fmt.Sprintf("http://%s:8083/d/rYdddlPWk/node-exporter-full?orgId=1&refresh=1m&var-DS_PROMETHEUS=default&var-job=node&var-node=%s:9990",
		monitor.Config.Grafana.SSHHost.Host, u.Info.IP)

	ctx := context.Background()

	{

		ret, err := monitor.PromCli.Query(ctx, fmt.Sprintf(HostNameInfoMetrics, u.Info.IP))
		if err != nil {
			errorList = append(errorList, fmt.Errorf("prom host name query error: %w", err))
		} else {
			if len(ret.Data.Result) != 0 {
				u.HostName = ret.Data.Result[0].Metric["nodename"]
			} else {
				errorList = append(errorList, fmt.Errorf("prom host name query not found node name"))
			}
		}
	}

	{
		ret, err := monitor.PromCli.Query(ctx, fmt.Sprintf(HostCpuCountMetrics, u.Info.IP))
		if err != nil {
			errorList = append(errorList, fmt.Errorf("prom host cpu count query error: %w", err))
		} else {
			if len(ret.Data.Result) != 0 && len(ret.Data.Result[0].Value) != 0 {
				count := ret.Data.Result[0].Value[1].String()
				u.Quota = count + "C"
			} else {
				errorList = append(errorList, fmt.Errorf("prom host cpu count query not found result"))
			}
		}
	}
	{
		ret, err := monitor.PromCli.Query(ctx, fmt.Sprintf(HostMemTotalMetrics, u.Info.IP))
		if err != nil {
			errorList = append(errorList, fmt.Errorf("prom host memory query error: %w", err))
		}
		if len(ret.Data.Result) != 0 && len(ret.Data.Result[0].Value) != 0 {
			total, err := ret.Data.Result[0].Value[1].Int64()
			if err != nil {
				errorList = append(errorList, fmt.Errorf("prom host memory query not found result"))
			} else {
				totalGB := int(total / 1000_000_000)
				u.Quota = u.Quota + fmt.Sprint(totalGB) + "G"
			}
		}
	}
	{
		u.CpuUsage = 100 * PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf(HostCpuUsageMetrics, u.Info.IP, u.Info.IP), "$.data.result[0].value.[1]")
		u.MemoryUsage = 100 * PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf(HostMemUsageMetrics, u.Info.IP, u.Info.IP), "$.data.result[0].value.[1]")
		u.DiskUsage = 100 * PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf(HostDiskUsageMetrics, u.Info.IP, u.Info.IP), "$.data.result[0].value.[1]")
		u.NetUpload = PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf(HostNetUploadMetrics, u.Info.IP), "$.data.result[0].value.[1]")
		u.NetDownload = PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf(HostNetDownloadMetrics, u.Info.IP), "$.data.result[0].value.[1]")
	}
	{
		u.LoadScore = u.CpuUsage*0.5 + u.MemoryUsage*0.4 + u.DiskUsage*0.1
	}
	return nil
}
