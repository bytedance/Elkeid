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
	"github.com/bytedance/Elkeid/agent/buffer"
	"github.com/bytedance/Elkeid/agent/host"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/resource"
	"github.com/bytedance/Elkeid/agent/transport"
	"github.com/bytedance/Elkeid/agent/transport/connection"
	"github.com/coreos/go-systemd/daemon"
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
	rec.Data.Fields["state"], rec.Data.Fields["state_detail"] = agent.State()
	rec.Data.Fields["idc"] = connection.IDC.Load().(string)
	rec.Data.Fields["region"] = connection.Region.Load().(string)
	rec.Data.Fields["net_mode"] = connection.NetMode.Load().(string)
	s := connection.DefaultStatsHandler.GetStats(now)
	// for all grpc
	rec.Data.Fields["rx_speed"] = strconv.FormatFloat(s.RxSpeed, 'f', 8, 64)
	rec.Data.Fields["tx_speed"] = strconv.FormatFloat(s.TxSpeed, 'f', 8, 64)
	cpuPercent, rss, readSpeed, writeSpeed, fds, startAt, err := resource.GetProcResouce(os.Getpid())
	if err != nil {
		zap.S().Error(err)
	} else {
		rec.Data.Fields["cpu"] = strconv.FormatFloat(cpuPercent, 'f', 8, 64)
		rec.Data.Fields["rss"] = strconv.FormatUint(rss, 10)
		rec.Data.Fields["read_speed"] = strconv.FormatFloat(readSpeed, 'f', 8, 64)
		rec.Data.Fields["write_speed"] = strconv.FormatFloat(writeSpeed, 'f', 8, 64)
		rec.Data.Fields["pid"] = strconv.Itoa(os.Getpid())
		rec.Data.Fields["nfd"] = strconv.FormatInt(int64(fds), 10)
		rec.Data.Fields["start_time"] = strconv.FormatInt(startAt, 10)
	}
	txTPS, rxTPX := transport.GetState(now)
	// for transfer service
	rec.Data.Fields["tx_tps"] = strconv.FormatFloat(txTPS, 'f', 8, 64)
	rec.Data.Fields["rx_tps"] = strconv.FormatFloat(rxTPX, 'f', 8, 64)
	rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(agent.WorkingDirectory, "plugin"), 10)
	rec.Data.Fields["ngr"] = strconv.Itoa(runtime.NumGoroutine())
	rec.Data.Fields["nproc"] = strconv.Itoa(runtime.NumCPU())
	rec.Data.Fields["total_mem"] = strconv.FormatUint(resource.GetMemTotal(), 10)
	if runtime.GOOS == "linux" {
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
		rec.Data.Fields["host_serial"], rec.Data.Fields["host_id"], rec.Data.Fields["host_model"], rec.Data.Fields["host_vendor"] = resource.GetHostInfo()
		rec.Data.Fields["dns"] = resource.GetDNS()
		rec.Data.Fields["gateway"] = resource.GetGateway()
	}
	rec.Data.Fields["cpu_name"] = resource.GetCPUName()
	rec.Data.Fields["boot_time"] = strconv.FormatUint(resource.GetBootTime(), 10)
	if cpuPercents, err := cpu.Percent(0, false); err == nil && len(cpuPercents) != 0 {
		rec.Data.Fields["cpu_usage"] = strconv.FormatFloat(cpuPercents[0]/100, 'f', 8, 64)
	}
	if mem, err := mem.VirtualMemory(); err == nil {
		rec.Data.Fields["mem_usage"] = strconv.FormatFloat(mem.UsedPercent/100, 'f', 8, 64)
	}
	zap.S().Infof("agent heartbeat completed: %+v", rec.Data.Fields)
	daemon.SdNotify(false, "WATCHDOG=1")
	buffer.WriteRecord(rec)
}
func getPlgStat(now time.Time) {
	plgs := plugin.GetAll()
	for _, plg := range plgs {
		if !plg.IsExited() {
			rec := &proto.Record{
				DataType:  1001,
				Timestamp: now.Unix(),
				Data: &proto.Payload{
					Fields: map[string]string{"name": plg.Name(), "pversion": plg.Version()},
				},
			}
			cpuPercent, rss, readSpeed, writeSpeed, fds, startAt, err := resource.GetProcResouce(plg.Pid())
			if err != nil {
				zap.S().Error(err)
			} else {
				rec.Data.Fields["cpu"] = strconv.FormatFloat(cpuPercent, 'f', 8, 64)
				rec.Data.Fields["rss"] = strconv.FormatUint(rss, 10)
				rec.Data.Fields["read_speed"] = strconv.FormatFloat(readSpeed, 'f', 8, 64)
				rec.Data.Fields["write_speed"] = strconv.FormatFloat(writeSpeed, 'f', 8, 64)
				rec.Data.Fields["pid"] = strconv.Itoa(plg.Pid())
				rec.Data.Fields["nfd"] = strconv.FormatInt(int64(fds), 10)
				rec.Data.Fields["start_time"] = strconv.FormatInt(startAt, 10)
			}
			rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(plg.GetWorkingDirectory(), ""), 10)
			RxSpeed, TxSpeed, RxTPS, TxTPS := plg.GetState()
			rec.Data.Fields["rx_tps"] = strconv.FormatFloat(RxTPS, 'f', 8, 64)
			rec.Data.Fields["tx_tps"] = strconv.FormatFloat(TxTPS, 'f', 8, 64)
			rec.Data.Fields["rx_speed"] = strconv.FormatFloat(RxSpeed, 'f', 8, 64)
			rec.Data.Fields["tx_speed"] = strconv.FormatFloat(TxSpeed, 'f', 8, 64)
			zap.S().Infof("plugin heartbeat completed:%+v", rec.Data.Fields)
			buffer.WriteRecord(rec)
		}
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
