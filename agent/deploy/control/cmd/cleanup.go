/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

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
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func unique(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// cleanupCmd represents the cleanup command
var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "sysvinit" {
			// cleanup /elkeid-agent
			exec.Command("umount", "/elkeid-agent/cpu").Run()
			exec.Command("umount", "/elkeid-agent/memory").Run()
			exec.Command("umount", "/elkeid-agent/named").Run()
			os.RemoveAll("/elkeid-agent")
			// cleanup invalid process in cgroup
			cg, err := NewCGroup(serviceName)
			if err == nil {
				var resetPids []int
				for _, t := range []string{"named", "cpu", "memory"} {
					if pids, err := cg.GetProcs(t); err == nil {
						for _, pid := range pids {
							cwd, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
							if err != nil {
								continue
							}
							if strings.HasPrefix(cwd, filepath.Clean(agentWorkDir)) {
								continue
							}
							// only reset cgroup when process exists && process's cwd is not in agent work dir
							// maybe reset collector app cmd?
							resetPids = append(resetPids, pid)
						}
					}
				}
				if len(resetPids) != 0 {
					resetPids = unique(resetPids)
					cg, err := NewCGroup("/")
					if err == nil {
						for _, pid := range resetPids {
							cg.AddProc(pid)
						}
					}
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(cleanupCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cleanupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cleanupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
