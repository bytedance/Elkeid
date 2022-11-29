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
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/nightlyone/lockfile"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func CheckPids(pids []int) (res []int) {
	for _, pid := range pids {
		proc, _ := os.FindProcess(pid)
		if err := proc.Signal(syscall.Signal(0)); err == nil {
			res = append(res, pid)
		}
	}
	return
}

func GetProcsFromProc(pid int) (res []int, err error) {
	if pid < 2 {
		return nil, errors.New("invalid pid")
	}
	var procs []*process.Process
	procs, err = process.Processes()
	if err == nil {
		procMap := map[int32]struct{}{int32(pid): {}}
		for _, proc := range procs {
			if proc.Pid < 2 {
				continue
			}
			ppid, err := proc.Ppid()
			if err != nil {
				continue
			}
			if _, ok := procMap[ppid]; ok {
				procMap[proc.Pid] = struct{}{}
			}
		}
		for k := range procMap {
			res = append(res, int(k))
		}
	}
	return
}
func GetProcsFromCGroup() (res []int, err error) {
	cgroup, err := LoadCGroup(serviceName)
	if err != nil {
		return nil, err
	}
	return cgroup.GetProcs("named")
}
func GetProcs(pid int) (res []int, err error) {
	res, err = GetProcsFromCGroup()
	if err == nil && len(res) != 0 {
		return
	}
	return GetProcsFromProc(pid)
}
func sysvinitStop() error {
	os.RemoveAll(crontabFile)
	file, err := lockfile.New(agentPidFile)
	if err != nil {
		return err
	}
	p, err := file.GetOwner()
	if err == nil {
		var pids []int
		pids, err := GetProcs(p.Pid)
		if err != nil {
			return err
		}
		for _, pid := range pids {
			syscall.Kill(-pid, syscall.SIGTERM)
		}
		ticker := time.NewTicker(time.Millisecond * time.Duration(100))
		defer ticker.Stop()
		timeout := time.NewTimer(time.Second * time.Duration(30))
		i := 0
		defer timeout.Stop()
		for {
			select {
			case <-ticker.C:
				pids = CheckPids(pids)
				if len(pids) == 0 {
					return nil
				}
				if i%50 == 0 {
					fmt.Printf("wait %v subprocess to exit...\n", len(pids))
				}
				i++
			case <-timeout.C:
				fmt.Fprintln(os.Stderr, "stop timeout, will kill all subprocess...")
				for _, pid := range pids {
					syscall.Kill(-pid, syscall.SIGKILL)
				}
				return nil
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
			cobra.CheckErr(sysvinitStop())
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
