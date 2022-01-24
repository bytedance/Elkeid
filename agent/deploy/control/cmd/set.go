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
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:   "set",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.Flags().NFlag() == 0 {
			cobra.CheckErr(cmd.Help())
		}
		cmd.Flags().Visit(
			func(f *pflag.Flag) {
				switch f.Name {
				case "service_type":
					if f.Value.String() != "systemd" && f.Value.String() != "sysvinit" {
						cobra.CheckErr(cmd.Help())
					}
					viper.Set("service_type", f.Value)
				case "id":
					viper.Set("specified_id", f.Value)
				case "idc":
					viper.Set("specified_idc", f.Value)
				case "region":
					viper.Set("specified_region", f.Value)
				}
				cobra.CheckErr(viper.WriteConfig())
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// setCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	setCmd.Flags().String("service_type", "", "systemd or sysvinit")
	setCmd.Flags().String("id", "", "id of agent")
	setCmd.Flags().String("idc", "", "idc of agent")
	setCmd.Flags().String("region", "", "region of agent")
}
