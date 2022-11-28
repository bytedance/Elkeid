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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// restartCmd represents the restart command
var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "restart", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
			os.RemoveAll(crontabFile)
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			err := sysvinitStop()
			cobra.CheckErr(err)

			err = sysvinitStart()
			cobra.CheckErr(os.WriteFile(crontabFile, []byte(crontabContent), 0600))
			exec.Command("service", "cron", "restart").Run()
			exec.Command("service", "crond", "restart").Run()
			cobra.CheckErr(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(restartCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// restartCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// restartCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
