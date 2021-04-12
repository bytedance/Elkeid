package report

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/agent/global"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/transport"
	"github.com/prometheus/procfs"
	"go.uber.org/zap"
)

type Heart struct {
	io       uint64
	cpu      float64
	sys      float64
	lastFree time.Time
}

func (h *Heart) Beat() {
	report := make(map[string]string)
	p, err := procfs.Self()
	if err != nil {
		zap.S().Panic(err)
	}
	stat, err := p.Stat()
	if err != nil {
		zap.S().Panic(err)
	}
	io, err := p.IO()
	if err != nil {
		zap.S().Panic(err)
	}
	sys, err := procfs.NewDefaultFS()
	if err != nil {
		zap.S().Panic(err)
	}
	sysStat, err := sys.Stat()
	if err != nil {
		zap.S().Panic(err)
	}
	sysMem, err := sys.Meminfo()
	if err != nil {
		zap.S().Panic(err)
	}
	if stat.RSS*os.Getpagesize() > 100*1024*1024 {
		if time.Now().Sub(h.lastFree) <= time.Minute*5 {
			zap.S().Panic("Force GC frequency too fast")
		}
		debug.FreeOSMemory()
		h.lastFree = time.Now()
		if err != nil {
			zap.S().Panic(err)
		}
	}
	report["kernel_version"] = global.KernelVersion
	report["platform"] = global.Platform
	report["platform_version"] = global.PlatformVersion
	report["memory"] = strconv.Itoa(stat.RSS * os.Getpagesize())
	report["net_type"] = transport.NetMode
	report["data_type"] = "1000"
	report["timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	if h.sys == 0 {
		report["cpu"] = strconv.FormatFloat(0, 'f', 5, 64)

	} else {
		report["cpu"] = strconv.FormatFloat(float64(runtime.NumCPU())*(stat.CPUTime()-h.cpu)/(getTotal(sysStat)-h.sys), 'f', 5, 64)
	}
	report["io"] = strconv.FormatUint(io.ReadBytes+io.WriteBytes-h.io, 10)
	report["slab"] = strconv.FormatUint(sysMem.Slab, 10)
	plugins := []struct {
		RSS     int     `json:"rss"`
		IO      uint64  `json:"io"`
		CPU     float64 `json:"cpu"`
		Name    string  `json:"name"`
		Version string  `json:"version"`
		Pid     int     `json:"pid"`
		QPS     float64 `json:"qps"`
	}{}
	s, err := plugin.GetServer()
	if err == nil {
		s.ForEach(func(k string, p *plugin.Plugin) {
			item := struct {
				RSS     int     `json:"rss"`
				IO      uint64  `json:"io"`
				CPU     float64 `json:"cpu"`
				Name    string  `json:"name"`
				Version string  `json:"version"`
				Pid     int     `json:"pid"`
				QPS     float64 `json:"qps"`
			}{Name: p.Name(), Version: p.Version(), Pid: p.PID()}
			proc, err := procfs.NewProc(p.PID())
			if err == nil {
				stat, err := proc.Stat()
				if err == nil {
					item.RSS = stat.RSS * os.Getpagesize()
				}
				if p.CPU != 0 {
					item.CPU = float64(runtime.NumCPU()) * (stat.CPUTime() - p.CPU) / (getTotal(sysStat) - h.sys)
				}
				io, err := proc.IO()
				if err == nil {
					item.IO = io.ReadBytes + io.WriteBytes - p.IO
				}
				item.QPS = float64(p.Counter.Swap(0)) / 30.0
				p.CPU = stat.CPUTime()
				p.IO = io.ReadBytes + io.WriteBytes
			}
			plugins = append(plugins, item)
		})
	}
	encodedPlugins, err := json.Marshal(plugins)
	report["plugins"] = string(encodedPlugins)
	zap.S().Infof("%+v", report)
	select {
	case global.GrpcChannel <- []*global.Record{{Message: report}}:
	default:
		zap.S().Panic("Detected channel is full")
	}
	h.sys = getTotal(sysStat)
	h.cpu = stat.CPUTime()
	h.io = io.ReadBytes + io.WriteBytes
}

func Run() {
	defer func() {
		if err := recover(); err != nil {
			time.Sleep(time.Second)
			panic(err)
		}
	}()
	ticker := time.NewTicker(time.Second * 30)
	h := &Heart{}
	h.Beat()
	for {
		select {
		case <-ticker.C:
			h.Beat()
		}
	}
}
func getTotal(sysStat procfs.Stat) float64 {
	return sysStat.CPUTotal.Idle + sysStat.CPUTotal.IRQ + sysStat.CPUTotal.Iowait + sysStat.CPUTotal.Nice + sysStat.CPUTotal.SoftIRQ + sysStat.CPUTotal.System + sysStat.CPUTotal.User
}
