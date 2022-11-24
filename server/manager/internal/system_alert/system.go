package system_alert

import "github.com/bytedance/Elkeid/server/manager/biz/common"

type AlertLocation struct {
	Type     string `json:"type" bson:"type"`
	Hostname string `json:"hostname" bson:"hostname"`
	HostIP   string `json:"hostip" bson:"hostip"`
	Service  string `json:"service" bson:"service"`
}
type Alert struct {
	ID          string        `bson:"id" json:"id"`
	Name        string        `bson:"name" json:"name"`
	Content     string        `bson:"content" json:"content"`
	Severity    string        `bson:"severity" json:"severity"`
	Location    AlertLocation `bson:"location" json:"location"`
	Status      string        `bson:"status" json:"status"`
	Suggest     string        `bson:"suggest" json:"suggest"`
	Time        int64         `bson:"time" json:"time"`
	FiringTime  int64         `bson:"firing_time" json:"firing_time"`
	ResolveTime int64         `bson:"resolve_time" json:"resolve_time"`
}

var SystemAlertHeaders = common.MongoDBDefs{
	{Key: "id", Header: "id"},
	{Key: "name", Header: "name"},
	{Key: "content", Header: "content"},
	{Key: "location.type", Header: "node_type"},
	{Key: "location.hostname", Header: "host_name"},
	{Key: "location.hostip", Header: "host_ip"},
	{Key: "location.service", Header: "service"},
	{Key: "severity", Header: "severity"},
	{Key: "status", Header: "status"},
	{Key: "suggest", Header: "suggest"},
	{Key: "time", Header: "time"},
}
