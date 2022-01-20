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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// disableCmd represents the disable command
var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("service_type") == "systemd" {
			cmd := exec.Command("systemctl", "disable", serviceName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cobra.CheckErr(cmd.Run())
		} else if viper.GetString("service_type") == "sysvinit" {
			_, err := exec.LookPath("update-rc.d")
			if err == nil {
				res, err := exec.Command("update-rc.d", "-f", serviceName, "remove").CombinedOutput()
				if err != nil {
					cobra.CheckErr(fmt.Errorf("%w: %v", err, string(res)))
				}
				return
			}
			_, err = exec.LookPath("chkconfig")
			if err == nil {
				res, err := exec.Command("chkconfig", "--del", serviceName).CombinedOutput()
				if err != nil {
					cobra.CheckErr(fmt.Errorf("%w: %v", err, string(res)))
				}
				return
			}
			cobra.CheckErr(errors.New("no available service management tool"))
		}
	},
}

func init() {
	rootCmd.AddCommand(disableCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// disableCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// disableCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
