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
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func unset(key string) error {
	configMap := viper.AllSettings()
	delete(configMap, key)
	buf := bytes.NewBuffer(nil)
	for k, v := range configMap {
		fmt.Fprintf(buf, "%v = %v", k, v)
	}
	err := viper.ReadConfig(buf)
	if err != nil {
		return err
	}
	return viper.WriteConfig()
}

// unsetCmd represents the unset command
var unsetCmd = &cobra.Command{
	Use:   "unset",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.Flags().NFlag() == 0 {
			cobra.CheckErr(cmd.Help())
		}
		cmd.Flags().Visit(
			func(f *pflag.Flag) {
				switch f.Name {
				case "service_type":
					unset("service_type")
				case "id":
					unset("id")
				case "idc":
					unset("idc")
				case "region":
					unset("region")
				}
				cobra.CheckErr(viper.WriteConfig())
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(unsetCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// unsetCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// unsetCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	unsetCmd.Flags().Bool("service_type", false, "")
	unsetCmd.Flags().Bool("id", false, "")
	unsetCmd.Flags().Bool("idc", false, "")
	unsetCmd.Flags().Bool("region", false, "")
}
