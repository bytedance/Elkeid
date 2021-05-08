package main

import (
	"math/rand"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

type Namespace struct {
	Type  string `json:"type"`
	Inode uint32 `json:"inode"`
}
type Process struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Name      string `json:"name"`
	Cmdline   string `json:"cmdline"`
	Exe       string `json:"exe"`
	Sha256    string `json:"sha256"`
	UID       string `json:"uid"`
	Username  string `json:"username"`
	EUID      string `json:"euid"`
	Eusername string `json:"eusername"`
	Cwd       string `json:"cwd"`
	Session   int    `json:"session"`
	TTY       int    `json:"tty"`
	StartTime uint64 `json:"start_time"`
}

const MaxProcess = 5000

func GetProcess() (procs []Process, err error) {
	var allProc procfs.Procs
	var sys procfs.Stat
	allProc, err = procfs.AllProcs()
	if err != nil {
		return
	}
	sys, err = procfs.NewStat()
	if err != nil {
		return
	}
	if len(allProc) > MaxProcess {
		rand.Shuffle(len(allProc), func(i, j int) {
			allProc[i], allProc[j] = allProc[j], allProc[i]
		})
		allProc = allProc[:MaxProcess]
	}
	for _, p := range allProc {
		var err error
		proc := Process{PID: p.PID}
		proc.Exe, err = p.Executable()
		if err != nil {
			continue
		}
		_, err = os.Stat(proc.Exe)
		if err != nil {
			continue
		}
		status, err := p.NewStatus()
		if err == nil {
			proc.UID = status.UIDs[0]
			proc.EUID = status.UIDs[1]
			proc.Name = status.Name
		} else {
			continue
		}
		state, err := p.Stat()
		if err == nil {
			proc.PPID = state.PPID
			proc.Session = state.Session
			proc.TTY = state.TTY
			proc.StartTime = sys.BootTime + state.Starttime/100
		} else {
			continue
		}
		proc.Cwd, err = p.Cwd()
		if err != nil {
			continue
		}
		cmdline, err := p.CmdLine()
		if err != nil {
			continue
		} else {
			if len(cmdline) > 32 {
				cmdline = cmdline[:32]
			}
			proc.Cmdline = strings.Join(cmdline, " ")
			if len(proc.Cmdline) > 64 {
				proc.Cmdline = proc.Cmdline[:64]
			}
		}
		proc.Sha256, _ = GetSha256ByPath("/proc/" + strconv.Itoa(proc.PID) + "/exe")
		u, err := user.LookupId(proc.UID)
		if err == nil {
			proc.Username = u.Username
		}
		eu, err := user.LookupId(proc.EUID)
		if err == nil {
			proc.Eusername = eu.Username
		}
		procs = append(procs, proc)
	}
	return
}
