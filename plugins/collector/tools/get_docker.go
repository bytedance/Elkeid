package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

type container struct {
	pids    []int
	podName string
}

func main() {
	nsMapping := make(map[string]*container)
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
	innerNsMapping := make(map[string]*container)
	procs, err := procfs.AllProcs()
	if err != nil {
		return
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
	nsMapping = innerNsMapping
	for k, v := range nsMapping {
		fmt.Println(k, *v)
	}
}
