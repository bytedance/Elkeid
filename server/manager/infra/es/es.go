package es

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/olivere/elastic/v7"
)

type EsConfig struct {
	EsGzip       bool
	EsSniff      bool
	EsAuthUser   string
	EsAuthPasswd string
	Host         []string
	PSM          string
	Cluster      string
}

func NewEsClient(conf *EsConfig) (*elastic.Client, error) {
	client, err := elastic.NewClient(
		elastic.SetURL(conf.Host...), elastic.SetBasicAuth(conf.EsAuthUser, conf.EsAuthPasswd),
		elastic.SetSniff(conf.EsSniff),
		elastic.SetGzip(conf.EsGzip),
		elastic.SetErrorLog(ylog.GetLogger()))

	if err != nil {
		fmt.Printf("NEW_ES_ERROR %s\n", err.Error())
		return nil, err
	}
	return client, nil
}
