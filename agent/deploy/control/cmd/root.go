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
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

const (
	serviceName    = "elkeid-agent"
	agentWorkDir   = "/etc/elkeid/"
	ctlPidFile     = "/var/run/elkeidctl.pid"
	crontabContent = "* * * * * root /etc/elkeid/elkeidctl check\n"
	agentFile      = agentWorkDir + serviceName
	cfgFile        = agentWorkDir + "specified_env"
	serviceFile    = agentWorkDir + serviceName + ".service"
	sysvinitDir    = "/etc/init.d/"
	crontabFile    = "/etc/cron.d/" + serviceName
	cgroupPath     = agentWorkDir + "cgroup/"
	agentPidFile   = "/var/run/" + serviceName + ".pid"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "elkeidctl",
	Short: "A brief description of your application",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig, initCGroup)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigFile(cfgFile)
	viper.SetConfigType("props")
	// If a config file is found, read it in.
	viper.ReadInConfig()
}

func initCGroup() {
	if viper.GetString("service_type") == "sysvinit" {
		f, err := os.Open("/proc/self/cgroup")
		if err == nil {
			defer f.Close()
			s := bufio.NewScanner(f)
			var namedSet, cpuSet, memorySet bool
			for s.Scan() {
				fields := strings.Split(s.Text(), ":")
				if len(fields) < 3 {
					cobra.CheckErr(errors.New("bad entry of self cgroup"))
				}
				for _, subSystem := range strings.Split(fields[1], ",") {
					if subSystem == "cpu" && fields[2] != "/" {
						fmt.Printf("cpu cgroup has been set to: %v\n", fields[2])
						cpuSet = true
					} else if subSystem == "name=all" && fields[2] != "/" {
						fmt.Printf("named cgroup has been set to: %v\n", fields[2])
						namedSet = true
					} else if subSystem == "memory" && fields[2] != "/" {
						fmt.Printf("memory cgroup has been set to: %v\n", fields[2])
						memorySet = true
					}
				}
			}
			if namedSet || memorySet || cpuSet {
				cg, err := NewCGroup("/")
				if err != nil || (namedSet && cg.namedPath == "") ||
					(memorySet && cg.memoryPath == "") || (cpuSet && cg.cpuPath == "") {
					if err != nil {
						cobra.CheckErr(fmt.Errorf("cgroup has been set, but can't load cgroup: %v", err))
					} else {
						cobra.CheckErr(fmt.Errorf("cgroup has been set, but can't load cgroup: %+v", cg))
					}
				}
				err = cg.AddProc(os.Getpid())
				if err != nil {
					cobra.CheckErr(fmt.Errorf("cgroup has been set, but can't reset to default cgroup: %v", err))
				}
				fmt.Println("reset cgroup to default cgroup successfully")
			}
		}
	}
}
