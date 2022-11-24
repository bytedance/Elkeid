package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/levigross/grequests"
	"github.com/oliveagle/jsonpath"
	"net/url"
	"time"
)

type PromClient struct {
	Address  string `yaml:"address"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type PromPoint []json.Number

type PromVector struct {
	Metric map[string]string `json:"metric"`
	Value  PromPoint         `json:"value"`
}

type PromMatrix struct {
	Metric map[string]string `json:"metric"`
	Values []PromPoint       `json:"values"`
}

type PromQueryRetData struct {
	ResultType string       `json:"resultType"`
	Result     []PromVector `json:"result"`
}

type PromQueryRet struct {
	Status    string           `json:"status"`
	Data      PromQueryRetData `json:"data"`
	ErrorType string           `json:"errorType"`
	Error     string           `json:"error"`
}

type PromQueryRangeRetData struct {
	ResultType string       `json:"resultType"`
	Result     []PromMatrix `json:"result"`
}

type PromQueryRangeRet struct {
	Status    string                `json:"status"`
	Data      PromQueryRangeRetData `json:"data"`
	ErrorType string                `json:"errorType"`
	Error     string                `json:"error"`
}

func (cli PromClient) HttpGet(ctx context.Context, queryUrl string, ret interface{}) error {
	opts := grequests.RequestOptions{
		InsecureSkipVerify: true,
		Context:            ctx,
		Auth:               []string{cli.User, cli.Password},
		DialTimeout:        time.Second * 2,
		RequestTimeout:     time.Second * 10,
	}
	resp, err := grequests.Get(cli.Address+queryUrl, &opts)
	if err != nil {
		return fmt.Errorf("prometheus http client GET failed by %w", err)
	}
	err = resp.JSON(ret)
	if err != nil {
		return fmt.Errorf("prometheus http client decode json error by %w", err)
	}
	return nil
}

func (cli PromClient) Query(ctx context.Context, query string) (result PromQueryRet, err error) {
	queryUrl := "/api/v1/query?query=" + url.QueryEscape(query)
	err = cli.HttpGet(ctx, queryUrl, &result)
	return result, err
}

func (cli PromClient) QueryRange(ctx context.Context, query string, start, end int64, step int) (result PromQueryRangeRet, err error) {
	duration := end - start
	if duration >= 60*60*24 && step <= 30 {
		step = 60
	}
	if duration >= 60*60*24*7 && step <= 120 {
		step = 120
	}
	queryUrl := "/api/v1/query_range?start=" + fmt.Sprint(start) +
		"&end=" + fmt.Sprint(end) +
		"&step=" + fmt.Sprint(step) +
		"&query=" + url.QueryEscape(query)
	err = cli.HttpGet(ctx, queryUrl, &result)
	return result, err
}

func (cli PromClient) SearchMetrics(ctx context.Context, items []PromQueryItem, start, end int64, period int) (MetricsData, error) {
	data := MetricsData{
		StartTime:         start,
		EndTime:           end,
		Period:            period,
		MetricDataResults: make([]MetricsItem, 0),
	}

	for _, item := range items {
		ret, err := cli.QueryRange(ctx, item.Metrics, start, end, period)
		if err != nil {
			return MetricsData{}, fmt.Errorf("search metrics error by %w", err)
		}
		if ret.Status != "success" {
			return MetricsData{}, fmt.Errorf("prometheus query failed by %s", ret.Error)
		}
		metricsItem := MetricsItem{
			Name:       item.Name,
			DataPoints: make([]MetricsPoint, 0),
		}
		if len(ret.Data.Result) == 0 {
			data.MetricDataResults = append(data.MetricDataResults, metricsItem)
			continue
		}
		for _, p := range ret.Data.Result[0].Values {
			if len(p) == 2 {
				timestamp, ok1 := p[0].Int64()
				value, ok2 := p[1].Float64()
				if ok1 == nil && ok2 == nil {
					metricsItem.DataPoints = append(metricsItem.DataPoints, MetricsPoint{
						Timestamp: timestamp,
						Value:     value,
					})
				}
			}
		}
		data.MetricDataResults = append(data.MetricDataResults, metricsItem)
	}
	return data, nil
}

func (cli PromClient) QueryWithJsonPath(ctx context.Context, query string, path string) (ret interface{}, err error) {
	var result interface{}
	queryUrl := "/api/v1/query?query=" + url.QueryEscape(query)
	err = cli.HttpGet(ctx, queryUrl, &result)
	if err != nil {
		return
	}
	ret, err = jsonpath.JsonPathLookup(result, path)
	return ret, err
}

var PromCli PromClient
