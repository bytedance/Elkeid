package monitor

type MetricsPoint struct {
	Timestamp int64   `json:"Timestamp"`
	Value     float64 `json:"Value"`
}

type MetricsItem struct {
	Name       string         `json:"Name"`
	DataPoints []MetricsPoint `json:"DataPoints"`
}

type MetricsData struct {
	StartTime         int64         `json:"StartTime"`
	EndTime           int64         `json:"EndTime"`
	Period            int           `json:"Period"`
	MetricDataResults []MetricsItem `json:"MetricDataResults"`
}

type PromQueryItem struct {
	Name    string
	Metrics string
}
