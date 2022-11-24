package metrics

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"strings"
)

const (
	MonitorServiceUsageLow         = "low"
	MonitorServiceUsageMiddle      = "middle"
	MonitorServiceUsageHigh        = "high"
	MonitorServiceUsageUnavailable = "unavailable"
)

func UsageToStatus(usage int) string {
	if usage < 50 {
		return MonitorServiceUsageLow
	} else if usage < 80 {
		return MonitorServiceUsageMiddle
	} else {
		return MonitorServiceUsageHigh
	}
}

func GetAvgCpuByHosts(ctx context.Context, hosts []*monitor.HostInfo) float64 {
	count := len(hosts)
	if count == 0 {
		return 0
	}

	items := make([]string, 0)
	for _, host := range hosts {
		items = append(items, fmt.Sprintf("%s:.*", host.IP))
	}

	return PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf("sum(rate(node_cpu_seconds_total{mode!='idle',instance=~'%s'}[1m]))/sum(rate(node_cpu_seconds_total{instance=~'%s'}[1m]))",
		strings.Join(items, "|"), strings.Join(items, "|")), "$.data.result[0].value.[1]")
}

func GetAvgMemByHosts(ctx context.Context, hosts []*monitor.HostInfo) float64 {
	count := len(hosts)
	if count == 0 {
		return 0
	}

	items := make([]string, 0)
	for _, host := range hosts {
		items = append(items, fmt.Sprintf("%s:.*", host.IP))
	}

	return PromQueryJsonPathWithRetFloat(ctx, fmt.Sprintf("1-(sum(node_memory_MemAvailable_bytes{instance=~'%s'})/sum(node_memory_MemTotal_bytes{instance=~'%s'}))",
		strings.Join(items, "|"), strings.Join(items, "|")), "$.data.result[0].value.[1]")
}
