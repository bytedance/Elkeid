package metrics

import (
	"time"
)

func Init() {
	go func() {
		for {
			time.Sleep(time.Minute)
			runMonitorServiceHeartbeat()
		}
	}()
}

const (
	AgentCpuMetrics         = "sum by (agent_id)(elkeid_ac_agent_cpu{agent_id='%s'})"
	AgentMemoryMetrics      = "sum by (agent_id)(elkeid_ac_agent_rss{agent_id='%s'})"
	AgentDiskMetrics        = "sum by (agent_id)(elkeid_ac_agent_du{agent_id='%s'})"
	AgentNetUploadMetrics   = "sum by (agent_id)(elkeid_ac_agent_tx_speed{agent_id='%s'})"
	AgentNetDownloadMetrics = "sum by (agent_id)(elkeid_ac_agent_rx_speed{agent_id='%s'})"
	AgentDiskReadMetrics    = "sum by (agent_id)(elkeid_ac_agent_read_speed{agent_id='%s'})"
	AgentDiskWriteMetrics   = "sum by (agent_id)(elkeid_ac_agent_write_speed{agent_id='%s'})"

	HostNameInfoMetrics    = "node_uname_info{instance=~'%s:.*'}"
	HostCpuCountMetrics    = "count(count(node_cpu_seconds_total{instance=~'%s:.*'}) by (cpu))"
	HostMemTotalMetrics    = "node_memory_MemTotal_bytes{instance=~'%s:.*'}"
	HostCpuUsageMetrics    = "sum(rate(node_cpu_seconds_total{mode!='idle',instance=~'%s:.*'}[1m]))/sum(rate(node_cpu_seconds_total{instance=~'%s:.*'}[1m]))"
	HostMemUsageMetrics    = "1-(node_memory_MemAvailable_bytes{instance=~'%s:.*'}/node_memory_MemTotal_bytes{instance=~'%s:.*'})"
	HostDiskUsageMetrics   = "1-(node_filesystem_avail_bytes{instance=~'%s:.*',mountpoint='/',fstype!='rootfs'}/node_filesystem_size_bytes{instance=~'%s:.*',mountpoint='/',fstype!='rootfs'})"
	HostNetUploadMetrics   = "sum(rate(node_network_transmit_bytes_total{instance=~'%s:.*'}[1m]))"
	HostNetDownloadMetrics = "sum(rate(node_network_receive_bytes_total{instance=~'%s:.*'}[1m]))"

	HostCpuAvgUsageMetrics  = "sum(rate(node_cpu_seconds_total{mode!='idle'}[1m]))/sum(rate(node_cpu_seconds_total{}[1m]))"
	HostMemAvgUsageMetrics  = "1-(sum(node_memory_MemAvailable_bytes{})/sum(node_memory_MemTotal_bytes{}))"
	HostDiskAvgUsageMetrics = "1-(sum(node_filesystem_avail_bytes{mountpoint='/',fstype!='rootfs'})/sum(node_filesystem_size_bytes{mountpoint='/',fstype!='rootfs'}))"
)
