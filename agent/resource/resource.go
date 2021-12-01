package resource

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

var (
	procCache, _ = lru.New(10)
	pageSize     = os.Getpagesize()
	bootTime     uint64
)

func init() {
	uptimeBytes, err := os.ReadFile("/proc/stat")
	if err == nil {
		fields := strings.Fields(string(uptimeBytes))
		for i, f := range fields {
			if f == "btime" {
				bootTime, _ = strconv.ParseUint(fields[i+1], 10, 64)
			}
		}
	}
}

type ProcInfo struct {
	CPUPercent float64
	FdCnt      uint64
	RSS        uint64  //bytes
	ReadSpeed  float64 //Bps
	WriteSpeed float64 //Bps
	StartedAt  uint64  //unix timestamp
}
type ProcMetadata struct {
	TotalTime  uint64
	Utime      uint64
	Stime      uint64
	Cutime     uint64
	Cstime     uint64
	RSS        uint64
	StartTime  uint64
	ReadBytes  uint64
	WriteBytes uint64
	FdCnt      uint64
	UpdateTime time.Time
}

func GetDirSize(path string, except string) uint64 {
	var dirSize uint64 = 0
	readSize := func(path string, file os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !file.IsDir() {
			dirSize += uint64(file.Size())
		} else {
			if file.Name() == except {
				return filepath.SkipDir
			}
		}
		return nil
	}
	filepath.Walk(path, readSize)
	return dirSize
}

func GetBootTime() uint64 { return bootTime }
func GetProcInfo(pid int, now time.Time) (info ProcInfo, err error) {
	oldMetadata, ok := procCache.Get(pid)
	var procStatBytes []byte
	procStatBytes, err = os.ReadFile(path.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return
	}
	fields := strings.Fields(string(procStatBytes))
	metadata := ProcMetadata{}
	if len(fields) > 23 {
		metadata.Utime, err = strconv.ParseUint(fields[13], 10, 64)
		if err != nil {
			return
		}
		metadata.Stime, err = strconv.ParseUint(fields[14], 10, 64)
		if err != nil {
			return
		}
		metadata.Cutime, err = strconv.ParseUint(fields[15], 10, 64)
		if err != nil {
			return
		}
		metadata.Cstime, err = strconv.ParseUint(fields[16], 10, 64)
		if err != nil {
			return
		}
		metadata.StartTime, err = strconv.ParseUint(fields[21], 10, 64)
		if err != nil {
			return
		}
		metadata.RSS, err = strconv.ParseUint(fields[23], 10, 64)
		if err != nil {
			return
		}
	}
	var sysStatBytes []byte
	sysStatBytes, err = os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	fields = strings.Fields(string(sysStatBytes))
	if len(fields) > 10 {
		for i := 0; i < 10; i++ {
			subTime, err := strconv.ParseUint(fields[i], 10, 64)
			if err == nil {
				metadata.TotalTime += subTime
			}
		}
	}
	var procIOBytes []byte
	procIOBytes, err = os.ReadFile(path.Join("/proc", strconv.Itoa(pid), "io"))
	if err != nil {
		return
	}
	fields = strings.Fields(string(procIOBytes))
	if len(fields) > 11 {
		metadata.ReadBytes, err = strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return
		}
		metadata.WriteBytes, err = strconv.ParseUint(fields[11], 10, 64)
		if err != nil {
			return
		}
	}
	var fdEntries []fs.DirEntry
	fdEntries, err = os.ReadDir(path.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return
	}
	metadata.FdCnt = uint64(len(fdEntries))
	metadata.UpdateTime = now
	if ok {
		instant := now.Sub(oldMetadata.(ProcMetadata).UpdateTime).Seconds()
		if instant != 0 {
			oldMetadata := oldMetadata.(ProcMetadata)
			info.CPUPercent = float64(runtime.NumCPU()) * float64(metadata.Utime+metadata.Stime-oldMetadata.Utime-oldMetadata.Stime) / float64(metadata.TotalTime-oldMetadata.TotalTime)
			info.ReadSpeed = float64(metadata.ReadBytes-oldMetadata.ReadBytes) / (float64(instant))
			info.WriteSpeed = float64(metadata.WriteBytes-oldMetadata.WriteBytes) / (float64(instant))
		} else {
			info.ReadSpeed = float64(metadata.ReadBytes) / (float64(uint64(metadata.UpdateTime.Unix()) - (metadata.StartTime + bootTime)))
			info.WriteSpeed = float64(metadata.WriteBytes) / (float64(uint64(metadata.UpdateTime.Unix()) - (metadata.StartTime + bootTime)))
		}
	} else {
		info.ReadSpeed = float64(metadata.ReadBytes) / (float64(uint64(metadata.UpdateTime.Unix()) - (metadata.StartTime + bootTime)))
		info.WriteSpeed = float64(metadata.WriteBytes) / (float64(uint64(metadata.UpdateTime.Unix()) - (metadata.StartTime + bootTime)))
	}
	info.StartedAt = metadata.StartTime/100 + bootTime
	info.RSS = metadata.RSS * uint64(pageSize)
	info.FdCnt = metadata.FdCnt
	procCache.Add(pid, metadata)
	return
}
