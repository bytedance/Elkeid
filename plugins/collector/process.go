package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/plugins"
	"github.com/tklauser/go-sysconf"
	"go.uber.org/zap"
)

const ProcessScanIntervalMillSec = 100
const MaxProcessNum = 1500
const MaxFieldLen = 128

var (
	sysTime    = uint64(0)
	nproc      = uint64(0)
	clockTicks = uint64(100)
	bootTime   = uint64(0)
)

func init() {
	clkTck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	// ignore errors
	if err == nil {
		clockTicks = uint64(clkTck)
	}
	stat, err := os.ReadFile("/proc/stat")
	if err == nil {
		statStr := string(stat)
		lines := strings.Split(statStr, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "btime") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					bootTime, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
	}
}

type Process struct {
	PID        int     `json:"pid"`
	PPID       int     `json:"ppid"`
	Comm       string  `json:"name"`
	Cmdline    string  `json:"cmdline"`
	Exe        string  `json:"exe"`
	Checksum   string  `json:"checksum"`
	UID        int     `json:"uid"`
	Username   string  `json:"username"`
	EUID       int     `json:"euid"`
	Eusername  string  `json:"eusername"`
	Cwd        string  `json:"cwd"`
	Session    int     `json:"session"`
	TTY        int     `json:"tty"`
	StartTime  uint64  `json:"start_time"`
	CPUPercent float64 `json:"cpu_percent"`
	RSS        int64   `json:"rss"`
}

func GetProcessOpenedFiles(pid int) ([]string, error) {
	fds, err := os.ReadDir("/proc/" + strconv.Itoa(int(pid)) + "/fd")
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, fd := range fds {
		file, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/fd/" + fd.Name())
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}
func GetProcessCwd(pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/cwd")
}
func GetProcessExe(pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
}
func GetProcessCmdline(pid int) (string, error) {
	res, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return "", err
	}
	if len(res) == 0 {
		return "", nil
	}
	res = bytes.ReplaceAll(res, []byte{0}, []byte{' '})
	res = bytes.TrimSpace(res)
	return string(res), nil
}
func GetPids() (pids []int, err error) {
	var es []fs.DirEntry
	es, err = os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range es {
		pid, err := strconv.ParseInt(e.Name(), 10, 64)
		if err == nil {
			pids = append(pids, int(pid))
		}
	}
	return
}
func FlushSysVar() {
	t := uint64(0)
	stat, err := os.ReadFile("/proc/stat")
	if err == nil {
		statStr := string(stat)
		lines := strings.Split(statStr, "\n")
		if len(lines) > 0 {
			fields := strings.Fields(lines[0])
			for i, f := range fields {
				if i == 8 {
					break
				}
				u, _ := strconv.ParseUint(f, 10, 64)
				t += u
			}
		}
	}
	sysTime = t
}
func GetProcessStat(pid int) (comm string, ppid int, session int, tty int, cpuPercent float64, starttime uint64, rss int64, err error) {
	var stat []byte
	stat, err = os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if err != nil {
		return
	}
	statStr := string(stat)
	fields := strings.Fields(statStr)
	if len(fields) < 24 {
		err = errors.New("invalid stat format")
		return
	}
	if len(fields[1]) > 1 {
		comm = string(fields[1][1 : len(fields[1])-1])
	}
	ppid, _ = strconv.Atoi(fields[3])
	session, _ = strconv.Atoi(fields[5])
	tty, _ = strconv.Atoi(fields[6])
	utime, _ := strconv.ParseUint(fields[13], 10, 64)
	stime, _ := strconv.ParseUint(fields[14], 10, 64)
	starttime, _ = strconv.ParseUint(fields[21], 10, 64)
	rss, _ = strconv.ParseInt(fields[23], 10, 64)
	iotime := uint64(0)
	if len(fields) > 42 {
		iotime, _ = strconv.ParseUint(string(fields[42]), 10, 64)
	}
	cpuPercent = (float64((utime + stime + iotime)) / float64(sysTime)) * float64(nproc)
	starttime = (starttime / clockTicks) + bootTime
	return
}
func GetProcessStatus(pid int) (uid, euid int, err error) {
	var status []byte
	status, err = os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/status")
	if err != nil {
		return
	}
	lines := bytes.Split(status, []byte{'\n'})
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("Uid")) {
			lineStr := string(line)
			fields := strings.Fields(lineStr)
			if len(fields) > 2 {
				uid, _ = strconv.Atoi(fields[1])
				euid, _ = strconv.Atoi(fields[2])
			}
			break
		}
	}
	return
}
func GetProcess() {
	zap.S().Info("scanning process")
	FlushSysVar()
	pids, err := GetPids()
	if err != nil {
		return
	}
	procs := []Process{}
	for _, pid := range pids {
		if len(procs) > MaxProcessNum {
			break
		}
		proc := Process{
			PID: pid,
		}
		var err error
		proc.Comm, proc.PPID, proc.Session, proc.TTY, proc.CPUPercent, proc.StartTime, proc.RSS, err = GetProcessStat(pid)
		if err != nil {
			continue
		}
		proc.UID, proc.EUID, err = GetProcessStatus(pid)
		if err != nil {
			continue
		}
		proc.Username = GetUsername(proc.UID)
		proc.Eusername = GetUsername(proc.EUID)
		proc.Cmdline, err = GetProcessCmdline(pid)
		if err != nil {
			continue
		}
		if len(proc.Cmdline) > MaxFieldLen {
			proc.Cmdline = proc.Cmdline[:MaxFieldLen]
		}
		proc.Exe, err = GetProcessExe(pid)
		if err != nil {
			continue
		}
		proc.Checksum, _ = GetMd5ByPath(proc.Exe)
		if len(proc.Exe) > MaxFieldLen {
			proc.Exe = proc.Exe[:MaxFieldLen]
		}
		procs = append(procs, proc)
		time.Sleep(time.Millisecond * time.Duration(ProcessScanIntervalMillSec))
	}
	zap.S().Info("scan process done")
	data, _ := json.Marshal(procs)
	rec := &plugins.Record{
		DataType:  5000,
		Timestamp: time.Now().Unix(),
		Data: &plugins.Payload{
			Fields: map[string]string{"data": string(data)},
		},
	}
	Client.SendRecord(rec)
}
func init() {
	go func() {
		rand.Seed(time.Now().UnixNano())
		time.Sleep(time.Second * time.Duration(rand.Intn(600)))
		GetProcess()
		time.Sleep(time.Hour)
		SchedulerMu.Lock()
		Scheduler.AddFunc(fmt.Sprintf("%d * * * * ", rand.Intn(60)), GetProcess)
		SchedulerMu.Unlock()
	}()
}
