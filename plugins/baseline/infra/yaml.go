package infra

import (
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"os"
)

// BindYaml parsing of yaml files
func BindYaml(filePath string, yamlMap interface{}) error {
	var err error
	if f, err := os.Open(filePath); err != nil {
	} else {
		err = yaml.NewDecoder(f).Decode(yamlMap)
		return err
	}
	return err
}

// BindYamlViper Dynamic parsing of yaml files
func BindYamlViper(filePath string, fileType string) (v *viper.Viper, err error) {
	v = viper.New()
	v.SetConfigFile(filePath)
	v.SetConfigType(fileType)
	err = v.ReadInConfig()
	if err != nil {
		return
	}
	return
}
