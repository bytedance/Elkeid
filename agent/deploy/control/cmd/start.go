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
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/containerd/cgroups"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func V1() (systems []cgroups.Subsystem, err error) {
	systems, err = cgroups.V1()
	if err != nil {
		return
	}
	if _, err := os.Stat(filepath.Join(agentWorkDir, "cgroup", "cpu", "tasks")); err == nil {
		systems = append(systems, cgroups.NewCpu(filepath.Join(agentWorkDir, "cgroup")))
	}
	if _, err := os.Stat(filepath.Join(agentWorkDir, "cgroup", "memory", "tasks")); err == nil {
		systems = append(systems, cgroups.NewMemory(filepath.Join(agentWorkDir, "cgroup")))
	}
	return
}
func sysvinitStart() error {
	cmd := exec.Command(agentFile)
	cmd.Dir = agentWorkDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	for k, v := range viper.AllSettings() {
		cmd.Env = append(cmd.Env, k+"="+v.(string))
	}
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	err := cmd.Start()
	if err != nil {
		return err
	}
	// set cgroup
	quota := int64(10000)
	memLimit := int64(262144000)
	cg, err := cgroups.New(V1,
		cgroups.StaticPath(cgroupPath),
		&specs.LinuxResources{
			CPU: &specs.LinuxCPU{
				Quota: &quota,
			},
			Memory: &specs.LinuxMemory{
				Limit: &memLimit,
			},
		})
	if err == nil {
		return cg.AddProc(uint64(cmd.Process.Pid))
	}
	return err
}

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "start", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
			err := sysvinitStart()
			cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			cobra.CheckErr(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
