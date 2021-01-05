package health

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/bytedance/ByteDance-HIDS/agent/common"
	"github.com/bytedance/ByteDance-HIDS/agent/plugin"
	"github.com/bytedance/ByteDance-HIDS/agent/spec"
	"github.com/bytedance/ByteDance-HIDS/agent/transport"
	"github.com/prometheus/procfs"
	"go.uber.org/zap"
)

func getMemoryMap() map[string]string {
	memoryMap := make(map[string]string, 20)
	memoryStats := runtime.MemStats{}
	runtime.ReadMemStats(&memoryStats)
	memoryMap["data_type"] = "1003"
	memoryMap["alloc"] = strconv.FormatUint(memoryStats.Alloc, 10)
	memoryMap["total_alloc"] = strconv.FormatUint(memoryStats.TotalAlloc, 10)
	memoryMap["sys"] = strconv.FormatUint(memoryStats.Sys, 10)
	memoryMap["lookups"] = strconv.FormatUint(memoryStats.Lookups, 10)
	memoryMap["mallocs"] = strconv.FormatUint(memoryStats.Mallocs, 10)
	memoryMap["frees"] = strconv.FormatUint(memoryStats.Frees, 10)
	memoryMap["heap_alloc"] = strconv.FormatUint(memoryStats.HeapAlloc, 10)
	memoryMap["heap_sys"] = strconv.FormatUint(memoryStats.HeapSys, 10)
	memoryMap["heap_idle"] = strconv.FormatUint(memoryStats.HeapIdle, 10)
	memoryMap["heap_inuse"] = strconv.FormatUint(memoryStats.HeapInuse, 10)
	memoryMap["heap_released"] = strconv.FormatUint(memoryStats.HeapReleased, 10)
	memoryMap["heap_objects"] = strconv.FormatUint(memoryStats.HeapObjects, 10)
	memoryMap["stack_inuse"] = strconv.FormatUint(memoryStats.StackInuse, 10)
	memoryMap["stack_sys"] = strconv.FormatUint(memoryStats.StackSys, 10)
	memoryMap["mspan_inuse"] = strconv.FormatUint(memoryStats.MSpanInuse, 10)
	memoryMap["mspan_sys"] = strconv.FormatUint(memoryStats.MSpanSys, 10)
	memoryMap["buckhash_sys"] = strconv.FormatUint(memoryStats.BuckHashSys, 10)
	memoryMap["gc_sys"] = strconv.FormatUint(memoryStats.GCSys, 10)
	memoryMap["other_sys"] = strconv.FormatUint(memoryStats.OtherSys, 10)
	return memoryMap
}

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
		zap.Error(err)
		return
	}
	stat, err := p.Stat()
	if err != nil {
		zap.Error(err)
		return
	}
	io, err := p.IO()
	if err != nil {
		zap.Error(err)
		return
	}
	sys, err := procfs.NewDefaultFS()
	if err != nil {
		zap.Error(err)
		return
	}
	sysStat, err := sys.Stat()
	if err != nil {
		zap.Error(err)
		return
	}
	sysMem, err := sys.Meminfo()
	if err != nil {
		zap.Error(err)
		return
	}
	if stat.RSS*os.Getpagesize() > 100000000 {
		if time.Now().Sub(h.lastFree) <= time.Minute*5 {
			zap.S().Panic("Force GC frequency too fast")
		}
		debug.FreeOSMemory()
		h.lastFree = time.Now()
		if err != nil {
			zap.S().Panic(err)
		}
	}
	report["kernel_version"] = common.KernelVersion
	report["distro"] = common.Distro
	report["memory"] = strconv.Itoa(stat.RSS * os.Getpagesize())
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
	err = transport.Send(&spec.Data{report})
	if err != nil {
		zap.S().Error(err)
	}
	h.sys = getTotal(sysStat)
	h.cpu = stat.CPUTime()
	h.io = io.ReadBytes + io.WriteBytes
}
func getTotal(sysStat procfs.Stat) float64 {
	return sysStat.CPUTotal.Idle + sysStat.CPUTotal.IRQ + sysStat.CPUTotal.Iowait + sysStat.CPUTotal.Nice + sysStat.CPUTotal.SoftIRQ + sysStat.CPUTotal.System + sysStat.CPUTotal.User
}

func Start() {
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
