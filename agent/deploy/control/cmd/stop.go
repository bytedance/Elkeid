/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	"github.com/nightlyone/lockfile"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getProcTreeWithProc(pid int) (res []int, err error) {
	if pid == 0 || pid == 1 {
		return nil, errors.New("proc tree includes init")
	}
	var procs []*process.Process
	procs, err = process.Processes()
	if err == nil {
		procMap := map[int32]struct{}{int32(pid): {}}
		for _, proc := range procs {
			if proc.Pid == 0 || proc.Pid == 1 {
				return nil, errors.New("proc tree includes init")
			}
			ppid, err := proc.Ppid()
			if err != nil {
				continue
			}
			if _, ok := procMap[ppid]; ok {
				procMap[proc.Pid] = struct{}{}
				continue
			}
			if exe, err := proc.Exe(); err == nil && strings.HasPrefix(exe, agentWorkDir) && os.Getpid() != int(proc.Pid) {
				procMap[proc.Pid] = struct{}{}
				continue
			}
		}
		for k := range procMap {
			res = append(res, int(k))
		}
	}
	return
}
func getProcTreeWithCgroup(pid int) (res []int, err error) {
	var cg cgroups.Cgroup
	cg, err = cgroups.Load(V1, cgroups.StaticPath(cgroupPath))
	if err != nil {
		return
	}
	var procs []cgroups.Process
	procs, err = cg.Processes(cgroups.Cpu, false)
	if err == nil {
		for _, p := range procs {
			if p.Pid == 0 || p.Pid == 1 {
				return nil, errors.New("proc tree includes init")
			}
			res = append(res, int(p.Pid))
		}
	}
	if len(res) == 0 {
		err = errors.New("could not find procs")
	}
	return
}

func sysvinitStop() error {
	os.RemoveAll(crontabFile)
	file, _ := lockfile.New(agentPidFile)
	p, err := file.GetOwner()
	if err == nil {
		var getProcTree func(int) (res []int, err error)
		var pids []int
		pids, err := getProcTreeWithCgroup(p.Pid)
		// cgroup mode
		if err == nil {
			getProcTree = getProcTreeWithCgroup
		} else {
			// procfs mode
			pids, _ = getProcTreeWithProc(p.Pid)
			getProcTree = getProcTreeWithProc
		}
		for _, pid := range pids {
			syscall.Kill(pid, syscall.SIGTERM)
		}
		ticker := time.NewTicker(time.Millisecond * time.Duration(100))
		defer ticker.Stop()
		timeout := time.NewTimer(time.Second * time.Duration(30))
		defer timeout.Stop()
	OUT:
		for {
			select {
			case <-ticker.C:
				pids, _ := getProcTree(p.Pid)
				if len(pids) == 0 {
					break OUT
				}
			case <-timeout.C:
				pids, _ := getProcTree(p.Pid)
				for _, pid := range pids {
					syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	}
	return nil
}

// stopCmd represents the stop command
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "stop", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
			os.RemoveAll(crontabFile)
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			sysvinitStop()
		}
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
