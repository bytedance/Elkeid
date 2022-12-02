package metrics

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	. "github.com/bytedance/mockey"
	"github.com/oliveagle/jsonpath"
	"net/url"
	"strings"
	"testing"
)

func monitorGetAllHosts() []monitor.HostInfo {
	return []monitor.HostInfo{{
		ID:       "n4-127-0-0-1",
		IP:       "127.0.0.1",
		Services: []string{"HUB"},
	}}
}

func monitorPromCliQuery(cli monitor.PromClient, ctx context.Context, query string) (result monitor.PromQueryRet, err error) {
	queryUrl := "/api/v1/query?query=" + url.QueryEscape(query)
	queryUrl = strings.ReplaceAll(queryUrl, "instance", "exported_instance")
	err = cli.HttpGet(ctx, queryUrl, &result)
	return result, err
}

func monitorPromCliQueryWithJsonPath(cli monitor.PromClient, ctx context.Context, query string, path string) (ret interface{}, err error) {
	var result interface{}
	queryUrl := "/api/v1/query?query=" + url.QueryEscape(query)
	queryUrl = strings.ReplaceAll(queryUrl, "instance", "exported_instance")
	err = cli.HttpGet(ctx, queryUrl, &result)
	if err != nil {
		return
	}
	ret, err = jsonpath.JsonPathLookup(result, path)
	return ret, err
}

func TestUpdateHostUsage(t *testing.T) {
	InitPrometheusData()
	PatchConvey("UpdateHostUsage", t, func() {
		Mock(monitor.GetAllHosts).To(monitorGetAllHosts).Build()
		Mock(monitor.PromClient.Query).To(monitorPromCliQuery).Build()
		Mock(monitor.PromClient.QueryWithJsonPath).To(monitorPromCliQueryWithJsonPath).Build()
		UpdateHostUsage()
	})
}
