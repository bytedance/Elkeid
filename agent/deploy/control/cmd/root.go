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
	"github.com/spf13/cobra"

	"github.com/spf13/viper"
)

const (
	cfgFile        = "/etc/elkeid/specified_env"
	serviceName    = "elkeid-agent"
	serviceFile    = "/etc/elkeid/elkeid-agent.service"
	agentPidFile   = "/var/run/elkeid-agent.pid"
	agentFile      = "/etc/elkeid/elkeid-agent"
	agentWorkDir   = "/etc/elkeid/"
	sysvinitDir    = "/etc/init.d/"
	cgroupPath     = "/elkeid-agent"
	crontabContent = "* * * * * root /etc/elkeid/elkeidctl check\n"
	crontabFile    = "/etc/cron.d/elkeid-agent"
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
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigFile(cfgFile)
	viper.SetConfigType("props")
	// If a config file is found, read it in.
	viper.ReadInConfig()
}
