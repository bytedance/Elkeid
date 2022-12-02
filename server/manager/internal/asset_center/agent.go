package asset_center

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

const DEFAULT_OFFLINE_DURATION = 10 * 60

type AgentBasicInfo struct {
	AgentID            string   `bson:"agent_id"`
	ExtranetIPv4       []string `bson:"extranet_ipv4"`
	ExtranetIPv6       []string `bson:"extranet_ipv6"`
	IntranetIPv4       []string `bson:"intranet_ipv4"`
	IntranetIPv6       []string `bson:"intranet_ipv6"`
	Hostname           string   `bson:"hostname"`
	IDC                string   `bson:"idc"`
	LastHeartbeatTime  int64    `bson:"last_heartbeat_time"`
	FirstHeartbeatTime int64    `bson:"first_heartbeat_time"`
	Platform           string   `bson:"platform"`
	Tags               []string `bson:"tags"`
	Status             string   `bson:"status"`
	SourceIP           string   `bson:"source_ip"`
	SourcePort         int      `bson:"source_port"`
	CPU                float64  `bson:"cpu"`
	Memory             int64    `bson:"rss"`
	State              string   `bson:"state"`
	StateDetail        string   `bson:"state_detail"`
}

func (info AgentBasicInfo) GetStatus(current time.Time) string {
	if current.Unix()-info.LastHeartbeatTime > DEFAULT_OFFLINE_DURATION {
		return "offline"
	}
	if info.State == "abnormal" {
		return "abnormal"
	}
	return "running"
}

type AgentDetailInfo struct {
	AgentBasicInfo `bson:",inline"`
	BootAt         int64  `bson:"boot_at"`
	KernelVersion  string `bson:"kernel_version"`
	NetMode        string `bson:"net_mode"`
	Pid            int64  `bson:"pid"`
	Plugins        []struct {
		LastHeartbeatTime int64   `bson:"last_heartbeat_time"`
		Name              string  `bson:"name"`
		Type              string  `bson:"type"`
		Pid               int64   `bson:"pid"`
		Pversion          string  `bson:"pversion"`
		Status            string  `bson:"status"`
		StartedAt         int64   `bson:"started_at"`
		StartTime         int64   `bson:"start_time"`
		CPU               float64 `bson:"cpu"`
		Memory            int64   `bson:"rss"`
	} `bson:"plugins"`
	StartedAt       int64   `bson:"started_at"`
	Version         string  `bson:"version"`
	PlatformVersion string  `bson:"platform_version"`
	Load1           float64 `bson:"load_1"`
	Load5           float64 `bson:"load_5"`
	Load15          float64 `bson:"load_15"`
	CpuUsage        float64 `bson:"cpu_usage"`
	MemUsage        float64 `bson:"mem_usage"`
	TotalMem        int64   `bson:"total_mem"`
	Nproc           int64   `bson:"nproc"`
	HostSerial      string  `bson:"host_serial"`
	HostID          string  `bson:"host_id"`
	HostModel       string  `bson:"host_model"`
	HostVendor      string  `bson:"host_vendor"`
	CPUName         string  `bson:"cpu_name"`
	DNS             string  `bson:"dns"`
	Gateway         string  `bson:"gateway"`
	StartTime       int64   `bson:"start_time"`
	BootTime        int64   `bson:"boot_time"`
	State           string  `bson:"state"`
	StateDetail     string  `bson:"state_detail"`
}

// t2: current time, t1: agent time
func AgentStateToFilter(status string) (filter bson.M) {
	current := time.Now().Unix()
	switch status {
	case "running":
		filter = bson.M{"last_heartbeat_time": bson.M{"$gte": current - DEFAULT_OFFLINE_DURATION}, "state": bson.M{"$ne": "abnormal"}}
	case "abnormal":
		filter = bson.M{"last_heartbeat_time": bson.M{"$gte": current - DEFAULT_OFFLINE_DURATION}, "state": "abnormal"}
	case "offline":
		filter = bson.M{"last_heartbeat_time": bson.M{"$lt": current - DEFAULT_OFFLINE_DURATION}}
	}
	return
}
