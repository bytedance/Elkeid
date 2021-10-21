package heartbeat

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/agent/agent"
	"github.com/bytedance/Elkeid/agent/core"
	"github.com/bytedance/Elkeid/agent/host"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/resource"
	"github.com/bytedance/Elkeid/agent/transport"
	"github.com/bytedance/Elkeid/agent/transport/connection"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"go.uber.org/zap"
)

func getAgentStat(now time.Time) {
	rec := &proto.Record{
		DataType:  1000,
		Timestamp: now.Unix(),
		Data: &proto.Payload{
			Fields: map[string]string{},
		},
	}
	rec.Data.Fields["kernel_version"] = host.KernelVersion
	rec.Data.Fields["arch"] = host.Arch
	rec.Data.Fields["platform"] = host.Platform
	rec.Data.Fields["platform_family"] = host.PlatformFamily
	rec.Data.Fields["platform_version"] = host.PlatformVersion
	rec.Data.Fields["idc"] = connection.IDC
	rec.Data.Fields["region"] = connection.Region
	rec.Data.Fields["net_mode"] = connection.NetMode.Load().(string)
	s := connection.DefaultStatsHandler.GetStats(now)
	// for all grpc
	rec.Data.Fields["rx_speed"] = strconv.FormatFloat(s.RxSpeed, 'f', 8, 64)
	rec.Data.Fields["tx_speed"] = strconv.FormatFloat(s.TxSpeed, 'f', 8, 64)
	pinfo, err := resource.GetProcInfo(os.Getpid(), now)
	if err != nil {
		zap.S().Error(err)
	} else {
		rec.Data.Fields["cpu"] = strconv.FormatFloat(pinfo.CPUPercent, 'f', 8, 64)
		rec.Data.Fields["rss"] = strconv.FormatUint(pinfo.RSS, 10)
		rec.Data.Fields["read_speed"] = strconv.FormatFloat(pinfo.ReadSpeed, 'f', 8, 64)
		rec.Data.Fields["write_speed"] = strconv.FormatFloat(pinfo.WriteSpeed, 'f', 8, 64)
		rec.Data.Fields["pid"] = strconv.Itoa(os.Getpid())
		rec.Data.Fields["fd_cnt"] = strconv.FormatUint(pinfo.FdCnt, 10)
		rec.Data.Fields["started_at"] = strconv.FormatUint(pinfo.StartedAt, 10)
	}
	txTPS, rxTPX := transport.GetState(now)
	// for transfer service
	rec.Data.Fields["tx_tps"] = strconv.FormatFloat(txTPS, 'f', 8, 64)
	rec.Data.Fields["rx_tps"] = strconv.FormatFloat(rxTPX, 'f', 8, 64)
	rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(agent.WorkingDirectory, "plugin"), 10)
	rec.Data.Fields["grs"] = strconv.Itoa(runtime.NumGoroutine())
	rec.Data.Fields["nproc"] = strconv.Itoa(runtime.NumCPU())
	loadavgBytes, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(loadavgBytes))
		if len(fields) > 3 {
			rec.Data.Fields["load_1"] = fields[0]
			rec.Data.Fields["load_5"] = fields[1]
			rec.Data.Fields["load_15"] = fields[2]
			subFields := strings.Split(fields[3], "/")
			if len(subFields) > 1 {
				rec.Data.Fields["running_procs"] = subFields[0]
				rec.Data.Fields["total_procs"] = subFields[1]
			}
		}
	}
	rec.Data.Fields["boot_at"] = strconv.FormatUint(resource.GetBootTime(), 10)
	cpuPercents, err := cpu.Percent(0, false)
	if err != nil {
		rec.Data.Fields["sys_cpu"] = strconv.FormatFloat(cpuPercents[0], 'f', 8, 64)
	}
	mem, err := mem.VirtualMemory()
	if err != nil {
		rec.Data.Fields["sys_mem"] = strconv.FormatFloat(mem.UsedPercent, 'f', 8, 64)
	}
	zap.S().Infof("agent heartbeat completed:%+v", rec.Data.Fields)
	core.Transmission(rec, false)
}
func getPlgStat(now time.Time) {
	plgs := plugin.GetAll()
	for _, plg := range plgs {
		state := plg.GetState(now)
		rec := &proto.Record{
			DataType:  1001,
			Timestamp: now.Unix(),
			Data: &proto.Payload{
				Fields: map[string]string{"name": state.Name, "pversion": state.Version},
			},
		}
		rec.Data.Fields["rx_speed"] = strconv.FormatFloat(state.RxSpeed, 'f', 8, 64)
		rec.Data.Fields["tx_speed"] = strconv.FormatFloat(state.TxSpeed, 'f', 8, 64)
		rec.Data.Fields["rx_tps"] = strconv.FormatFloat(state.RxTPS, 'f', 8, 64)
		rec.Data.Fields["tx_tps"] = strconv.FormatFloat(state.TxTPS, 'f', 8, 64)
		rec.Data.Fields["cpu"] = strconv.FormatFloat(state.CPUPercent, 'f', 8, 64)
		rec.Data.Fields["rss"] = strconv.FormatUint(state.RSS, 10)
		rec.Data.Fields["read_speed"] = strconv.FormatFloat(state.ReadSpeed, 'f', 8, 64)
		rec.Data.Fields["write_speed"] = strconv.FormatFloat(state.WriteSpeed, 'f', 8, 64)
		rec.Data.Fields["pid"] = strconv.Itoa(state.Pid)
		rec.Data.Fields["started_at"] = strconv.FormatUint(state.StartedAt, 10)
		rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(plg.GetWorkingDirectory(), ""), 10)
		rec.Data.Fields["fd_cnt"] = strconv.FormatUint(state.FdCnt, 10)
		zap.S().Infof("plugin heartbeat completed:%+v", rec.Data.Fields)
		core.Transmission(rec, false)
	}
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	zap.S().Info("health daemon startup")
	getAgentStat(time.Now())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			{
				host.RefreshHost()
				getAgentStat(t)
				getPlgStat(t)
			}
		}
	}
}
