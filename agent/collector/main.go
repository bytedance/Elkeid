package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"cgithub.com/bytedance/Elkeid/agent/support/go/libmongoose"
	"github.com/bytedance/Elkeid/agent/collector/socket"
	"github.com/prometheus/procfs"
	"github.com/rjeczalik/notify"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	runtime.GOMAXPROCS(4)
}

type container struct {
	pids    []int
	podName string
}

func main() {
	// Connect to agent
	c, err := libmongoose.Connect("../../plugin.sock", "collector", "1.0.0.26")
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer c.Close()

	config := zap.NewProductionEncoderConfig()
	config.CallerKey = "source"
	config.TimeKey = "timestamp"
	config.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	remoteEncoder := zapcore.NewJSONEncoder(config)
	remoteWriter := zapcore.AddSync(&libmongoose.LoggerWriter{})
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "collector.log",
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(zapcore.NewCore(remoteEncoder, remoteWriter, zap.ErrorLevel), zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel))

	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	undo := zap.ReplaceGlobals(logger)
	defer undo()

	//Config logger
	txCh := make(chan map[string]string, 10)
	rand.Seed(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	disableProc := atomic.NewBool(true)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
		for {
			select {
			case <-ticker.C:
				ticker.Reset(time.Hour)
				procs, err := procfs.AllProcs()
				if err == nil && len(procs) <= 5000 {
					disableProc.Store(false)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour)
					init = false
				}
				if !disableProc.Load() {
					procs, err := GetProcess()
					if err == nil {
						data, err := json.Marshal(procs)
						if err == nil {
							rawdata := make(map[string]string)
							rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
							rawdata["data"] = string(data)
							rawdata["data_type"] = "5000"
							txCh <- rawdata
						}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour)
					init = false
				}
				sockets, err := socket.GetSocket(disableProc.Load())
				if err == nil {
					data, err := json.Marshal(sockets)
					if err == nil {
						rawdata := make(map[string]string)
						rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
						rawdata["data"] = string(data)
						rawdata["data_type"] = "5001"
						txCh <- rawdata
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
		defer ticker.Stop()
		lastUpdate := time.Time{}
		modifyCh := make(chan notify.EventInfo, 10)
		defer close(modifyCh)
		deleteCh := make(chan notify.EventInfo, 10)
		defer close(deleteCh)
		notify.Watch("/etc/shadow", modifyCh, notify.InModify)
		notify.Watch("/etc/passwd", modifyCh, notify.InModify)
		notify.Watch("/etc/shadow", deleteCh, notify.InDeleteSelf, notify.InMoveSelf)
		notify.Watch("/etc/passwd", deleteCh, notify.InDelete, notify.InMoveSelf)
		defer notify.Stop(modifyCh)
		defer notify.Stop(deleteCh)
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour)
					init = false
				}
				if time.Now().Sub(lastUpdate) > time.Minute*10 {
					users, err := GetUser()
					lastUpdate = time.Now()
					if err == nil {
						data, err := json.Marshal(users)
						if err == nil {
							rawdata := make(map[string]string)
							rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
							rawdata["data"] = string(data)
							rawdata["data_type"] = "5002"
							txCh <- rawdata
						}
					}
				}
			case <-modifyCh:
				if time.Now().Sub(lastUpdate) > time.Minute*10 {
					users, err := GetUser()
					lastUpdate = time.Now()
					if err == nil {
						data, err := json.Marshal(users)
						if err == nil {
							rawdata := make(map[string]string)
							rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
							rawdata["data"] = string(data)
							rawdata["data_type"] = "5002"
							txCh <- rawdata
						}
					}
				}
			case <-deleteCh:
				notify.Stop(modifyCh)
				notify.Stop(deleteCh)
				time.Sleep(time.Second)
				notify.Watch("/etc/shadow", modifyCh, notify.InModify)
				notify.Watch("/etc/passwd", modifyCh, notify.InModify)
				notify.Watch("/etc/shadow", deleteCh, notify.InDeleteSelf, notify.InMoveSelf)
				notify.Watch("/etc/passwd", deleteCh, notify.InDelete, notify.InMoveSelf)
			case <-ctx.Done():
				return
			}
		}
	}()

	mu := sync.RWMutex{}
	nsMapping := make(map[string]*container)
	go func() {
		self, err := procfs.Self()
		var mountNsInode, pidNsInode uint32
		if err != nil {
			return
		}
		nss, err := self.Namespaces()
		if err != nil {
			return
		}
		for _, ns := range nss {
			if ns.Type == "mnt" {
				mountNsInode = ns.Inode
			} else if ns.Type == "pid" {
				pidNsInode = ns.Inode
			}
		}
		if mountNsInode == 0 || pidNsInode == 0 {
			return
		}
		ticker := time.NewTicker(time.Hour * 6)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !disableProc.Load() {
					innerNsMapping := make(map[string]*container)
					procs, err := procfs.AllProcs()
					if err != nil {
						continue
					}
					for _, proc := range procs {
						nss, err := proc.Namespaces()
						if err != nil {
							continue
						}
						var procMountNsInode, procPidNsInode uint32
						for _, ns := range nss {
							if ns.Type == "mnt" {
								procMountNsInode = ns.Inode
							} else if ns.Type == "pid" {
								procPidNsInode = ns.Inode
							}
						}
						var podName string
						envs, err := proc.Environ()
						for _, env := range envs {
							fields := strings.Split(env, "=")
							if len(fields) == 2 && (strings.TrimSpace(fields[0]) == "POD_NAME" || strings.TrimSpace(fields[0]) == "MY_POD_NAME") {
								podName = strings.TrimSpace(fields[1])
							}
						}
						if procMountNsInode != 0 && procPidNsInode != 0 && procMountNsInode != mountNsInode && procPidNsInode != pidNsInode && podName != "" {
							key := strconv.FormatUint(uint64(procMountNsInode), 10) + "|" + strconv.FormatUint(uint64(procPidNsInode), 10)
							ct, ok := innerNsMapping[key]
							if ok {
								ct.pids = append(innerNsMapping[key].pids, proc.PID)
							} else {
								innerNsMapping[key] = &container{podName: podName}
							}
						}
					}
					mu.Lock()
					nsMapping = innerNsMapping
					mu.Unlock()
				}
			}
		}
	}()

	go func() {
		lastUpdate := time.Time{}
		init := true
		ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
		defer ticker.Stop()
		modifyCh := make(chan notify.EventInfo, 10)
		defer close(modifyCh)
		notify.Watch("/etc/cron.d", modifyCh, notify.InModify)
		notify.Watch("/etc/crontab", modifyCh, notify.InModify)
		notify.Watch("/var/spool/cron/crontabs/", modifyCh, notify.InModify)
		defer notify.Stop(modifyCh)
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour)
					init = false
				}
				if time.Now().Sub(lastUpdate) > time.Minute*10 {
					crons, err := GetCron("")
					lastUpdate = time.Now()
					if err == nil {
						data, err := json.Marshal(crons)
						if err == nil {
							rawdata := make(map[string]string)
							rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
							rawdata["data"] = string(data)
							rawdata["data_type"] = "5003"
							txCh <- rawdata
						}
					}
				}
			case <-modifyCh:
				if time.Now().Sub(lastUpdate) > time.Minute*10 {
					crons, err := GetCron("")
					lastUpdate = time.Now()
					if err == nil {
						data, err := json.Marshal(crons)
						if err == nil {
							rawdata := make(map[string]string)
							rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
							rawdata["data"] = string(data)
							rawdata["data_type"] = "5003"
							txCh <- rawdata
						}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				packages, err := GetDebPackage("/")
				if err == nil {
					data, err := json.Marshal(packages)
					if err == nil {
						rawdata := make(map[string]string)
						rawdata["pod_name"] = ""
						rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
						rawdata["data"] = string(data)
						rawdata["data_type"] = "5004"
						txCh <- rawdata
					}
				}
				mu.RLock()
				for _, v := range nsMapping {
					for _, pid := range v.pids {
						packages, err := GetDebPackage("/proc/" + strconv.Itoa(pid) + "/root")
						if err == nil {
							data, err := json.Marshal(packages)
							if err == nil {
								rawdata := make(map[string]string)
								rawdata["pod_name"] = v.podName
								rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
								rawdata["data"] = string(data)
								rawdata["data_type"] = "5004"
								txCh <- rawdata
							}
							break
						}
					}
				}
				mu.RUnlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				packages, err := GetRPMPackage("")
				if err == nil {
					data, err := json.Marshal(packages)
					if err == nil {
						rawdata := make(map[string]string)
						rawdata["pod_name"] = ""
						rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
						rawdata["data"] = string(data)
						rawdata["data_type"] = "5005"
						txCh <- rawdata
					}
				}
				mu.RLock()
				for _, v := range nsMapping {
					for _, pid := range v.pids {
						packages, err := GetRPMPackage("/proc/" + strconv.Itoa(pid) + "/root")
						if err == nil {
							data, err := json.Marshal(packages)
							if err == nil {
								rawdata := make(map[string]string)
								rawdata["pod_name"] = v.podName
								rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
								rawdata["data"] = string(data)
								rawdata["data_type"] = "5005"
								txCh <- rawdata
							}
							break
						}
					}
				}
				mu.RUnlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				packages, err := GetPypiPackage("")
				if err == nil {
					data, err := json.Marshal(packages)
					if err == nil {
						rawdata := make(map[string]string)
						rawdata["pod_name"] = ""
						rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
						rawdata["data"] = string(data)
						rawdata["data_type"] = "5006"
						txCh <- rawdata
					}
				}
				mu.RLock()
				for _, v := range nsMapping {
					for _, pid := range v.pids {
						packages, err := GetPypiPackage("/proc/" + strconv.Itoa(pid) + "/root")
						if err == nil {
							data, err := json.Marshal(packages)
							if err == nil {
								rawdata := make(map[string]string)
								rawdata["pod_name"] = v.podName
								rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
								rawdata["data"] = string(data)
								rawdata["data_type"] = "5006"
								txCh <- rawdata
							}
							break
						}
					}
				}
				mu.RUnlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				apt, err := GetAptConfig()
				if err == nil {
					apt["time"] = strconv.FormatInt(time.Now().Unix(), 10)
					apt["data_type"] = "5007"
					txCh <- apt
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				yum, err := GetYumConfig()
				if err == nil {
					yum["time"] = strconv.FormatInt(time.Now().Unix(), 10)
					yum["data_type"] = "5008"
					txCh <- yum
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				sshd, err := GetSshdConfig()
				if err == nil {
					sshd["time"] = strconv.FormatInt(time.Now().Unix(), 10)
					sshd["data_type"] = "5009"
					txCh <- sshd
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		init := true
		ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour * 24)
					init = false
				}
				units, err := GetSystemdUnit()
				if err == nil {
					data, err := json.Marshal(units)
					if err == nil {
						rawdata := make(map[string]string)
						rawdata["time"] = strconv.FormatInt(time.Now().Unix(), 10)
						rawdata["data"] = string(data)
						rawdata["data_type"] = "5010"
						txCh <- rawdata
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	buf := make([]map[string]string, 0, 100)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case rd := <-txCh:
			buf = append(buf, rd)
		case <-ticker.C:
			if len(buf) != 0 {
				err := c.Send(buf)
				buf = buf[:0]
				if err != nil {
					zap.S().Error(err)
					return
				}
			}
		}
	}
}
