package metrics

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/internal/monitor"
	"strconv"
)

func PromQueryJsonPathWithRetInt(ctx context.Context, query string, jsonPath string) int {
	ret, err := monitor.PromCli.QueryWithJsonPath(ctx, query, jsonPath)
	if err != nil {
		return -1
	} else {
		s, err := strconv.Atoi(fmt.Sprint(ret))
		if err != nil {
			return -1
		}
		return s
	}
}

func PromQueryJsonPathWithRetFloat(ctx context.Context, query string, jsonPath string) float64 {
	ret, err := monitor.PromCli.QueryWithJsonPath(ctx, query, jsonPath)
	if err != nil {
		return -1
	} else {
		s, err := strconv.ParseFloat(fmt.Sprint(ret), 64)
		if err != nil {
			return -1
		}
		return s
	}
}
