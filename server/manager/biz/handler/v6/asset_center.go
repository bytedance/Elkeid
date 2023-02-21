package v6

import (
	"regexp"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/baseline"
	"github.com/bytedance/Elkeid/server/manager/internal/vuln"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/cronjob"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

//goland:noinspection GoUnusedGlobalVariable
var UTC_OFFSET = "+0800"

func init() {
	UTC_OFFSET = strings.Fields(time.Now().String())[2]
}

type GeneralHostReq struct {
	IdList     []string         `form:"id_list" json:"id_list" binding:"required_without=Conditions"`
	Conditions *GeneralHostCond `form:"conditions" json:"conditions" binding:"required_without=IdList"`
}
type GeneralHostCond struct {
	Hostname string   `json:"hostname"`
	IP       string   `json:"ip"`
	Tags     []string `json:"tags"`
	Idc      []string `json:"idc"`
	Platform []string `json:"platform"`
	Status   []string `json:"status" binding:"omitempty,dive,oneof=running offline abnormal uninstall"`
	AgentID  string   `json:"agent_id"`
	Version  string   `json:"version"`
}

func (r *GeneralHostCond) GenerateFilter() bson.M {
	m := bson.M{}
	if r.Hostname != "" {
		m["hostname"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Hostname) + ".*",
			Options: "",
		}
	}
	if r.IP != "" {
		of := bson.A{bson.M{"intranet_ipv4": primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.IP) + ".*",
			Options: "",
		}},
			bson.M{"intranet_ipv6": primitive.Regex{
				Pattern: "^" + regexp.QuoteMeta(r.IP) + ".*",
				Options: "",
			}}, bson.M{"extranet_ipv4": primitive.Regex{
				Pattern: "^" + regexp.QuoteMeta(r.IP) + ".*",
				Options: "",
			}}, bson.M{"extranet_ipv6": primitive.Regex{
				Pattern: "^" + regexp.QuoteMeta(r.IP) + ".*",
				Options: "",
			}}}
		if orFilter, ok := m["$or"]; ok {
			m["$and"] = bson.A{
				bson.M{"$or": orFilter}, bson.M{"$or": of},
			}
		} else {
			m["$or"] = of
		}
	}
	if r.AgentID != "" {
		m["agent_id"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.AgentID) + ".*",
			Options: "",
		}
	}
	if r.Version != "" {
		m["version"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Version) + ".*",
			Options: "",
		}
	}
	if len(r.Tags) != 0 {
		m["tags"] = bson.M{"$in": r.Tags}
	}
	if len(r.Idc) != 0 {
		m["idc"] = bson.M{"$in": r.Idc}
	}
	if len(r.Platform) != 0 {
		m["platform"] = bson.M{"$in": r.Platform}
	}
	if len(r.Status) != 0 {
		of := bson.A{}
		for _, v := range r.Status {
			of = append(of, asset_center.AgentStateToFilter(v))
		}
		if orFilter, ok := m["$or"]; ok {
			m["$and"] = bson.A{
				bson.M{"$or": orFilter}, bson.M{"$or": of},
			}
		} else {
			m["$or"] = of
		}
	}
	return m
}
func (r *GeneralHostReq) GenerateFilter() bson.M {
	m := bson.M{}
	if len(r.IdList) != 0 {
		m["agent_id"] = bson.M{"$in": r.IdList}
	} else if r.Conditions != nil {
		m = r.Conditions.GenerateFilter()
	}
	return m
}

type DescribeHostsRespItem struct {
	AgentID            string   `json:"agent_id"`
	ExtranetIPv4       []string `json:"extranet_ipv4"`
	ExtranetIPv6       []string `json:"extranet_ipv6"`
	IntranetIPv4       []string `json:"intranet_ipv4"`
	IntranetIPv6       []string `json:"intranet_ipv6"`
	Hostname           string   `json:"hostname"`
	IDC                string   `json:"idc"`
	LastHeartbeatTime  int64    `json:"last_heartbeat_time"`
	FirstHeartbeatTime int64    `json:"first_heartbeat_time"`
	Platform           string   `json:"platform"`
	Tags               []string `json:"tags"`
	Risk               struct {
		Vuln      int64 `json:"vuln"`
		Alarm     int64 `json:"alarm"`
		Baseline  int64 `json:"baseline"`
		Event     int64 `json:"event"`
		RaspAlarm int64 `json:"rasp_alarm"`
		Virus     int64 `json:"virus"`
	} `json:"risk"`
	Status      string  `json:"status"`
	CPU         float64 `json:"cpu"`
	Memory      int64   `json:"memory"`
	StateDetail string  `json:"state_detail"`
}

func DescribeHosts(ctx *gin.Context) {
	now := time.Now()
	pq := &common.PageRequest{}
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection,
		options.Collection().SetReadPreference(readpref.PrimaryPreferred()))
	err := ctx.BindQuery(pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := GeneralHostCond{}
	err = ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   req.GenerateFilter(),
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeHostsRespItem
	presp, err := common.DBSearchPaginate(c, preq, func(c *mongo.Cursor) (err error) {
		info := asset_center.AgentBasicInfo{}
		err = c.Decode(&info)
		if err != nil {
			return
		}
		item := DescribeHostsRespItem{}
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
		item.Risk.Alarm, err = collection.CountDocuments(ctx, bson.M{
			"agent_id":       info.AgentID,
			"__alarm_status": 0,
			"__checked":      true,
			"__hit_wl":       false,
		})
		if err != nil {
			return
		}
		collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
		item.Risk.Vuln, err = collection.CountDocuments(ctx, bson.M{
			"agent_id":    info.AgentID,
			"status":      "unprocessed",
			"drop_status": "using",
			"action":      vuln.VulnActionBlock,
		})
		if err != nil {
			return
		}
		collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
		item.Risk.Baseline, err = collection.CountDocuments(ctx, bson.M{
			"agent_id": info.AgentID,
			"status":   "failed",
			"if_white": false,
		})
		if err != nil {
			return
		}
		collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmEventCollectionV1)
		item.Risk.Event, err = collection.CountDocuments(ctx, bson.M{
			"hosts.agent_id": info.AgentID,
			"status":         0,
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			return
		} else {
			item.AgentID = info.AgentID
			item.CPU = info.CPU
			item.ExtranetIPv4 = info.ExtranetIPv4
			item.ExtranetIPv6 = info.ExtranetIPv6
			item.FirstHeartbeatTime = info.FirstHeartbeatTime
			item.Hostname = info.Hostname
			item.IDC = info.IDC
			item.IntranetIPv4 = info.IntranetIPv4
			item.IntranetIPv6 = info.IntranetIPv6
			item.LastHeartbeatTime = info.LastHeartbeatTime
			item.Memory = info.Memory
			item.Platform = info.Platform
			item.StateDetail = info.StateDetail
			item.Status = info.GetStatus(now)
			item.Tags = info.Tags
			data = append(data, item)
		}
		return
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type DescribeHostDetailRespPluginItem struct {
	LastHeartbeatTime int64   `json:"last_heartbeat_time"`
	Name              string  `json:"name"`
	Pversion          string  `json:"pversion"`
	Status            string  `json:"status"`
	StartedAt         int64   `json:"started_at"`
	StartTime         int64   `json:"start_time"`
	CPU               float64 `json:"cpu"`
	Memory            int64   `json:"memory"`
}
type DescribeHostDetailResp struct {
	AgentID            string                             `json:"agent_id"`
	BootAt             int64                              `json:"boot_at"`
	ExtranetIPv4       []string                           `json:"extranet_ipv4"`
	ExtranetIPv6       []string                           `json:"extranet_ipv6"`
	FirstHeartbeatTime int64                              `json:"first_heartbeat_time"`
	Hostname           string                             `json:"hostname"`
	Idc                string                             `json:"idc"`
	IntranetIPv4       []string                           `json:"intranet_ipv4"`
	IntranetIPv6       []string                           `json:"intranet_ipv6"`
	KernelVersion      string                             `json:"kernel_version"`
	LastHeartbeatTime  int64                              `json:"last_heartbeat_time"`
	Status             string                             `json:"status"`
	NetMode            string                             `json:"net_mode"`
	Pid                int64                              `json:"pid"`
	Platform           string                             `json:"platform"`
	Plugins            []DescribeHostDetailRespPluginItem `json:"plugins"`
	Alarm              struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	} `json:"alarm"`
	RaspAlarm struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	} `json:"rasp_alarm"`
	Virus struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	} `json:"virus"`
	Vuln struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	} `json:"vuln"`
	Baseline struct {
		High   int `json:"high"`
		Medium int `json:"medium"`
		Low    int `json:"low"`
		Pass   int `json:"pass"`
	} `json:"baseline"`
	Event struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	} `json:"event"`
	RaspEvent struct {
		Critical int64 `json:"critical"`
		High     int64 `json:"high"`
		Medium   int64 `json:"medium"`
		Low      int64 `json:"low"`
	} `json:"rasp_event"`
	StartedAt       int64    `json:"started_at"`
	Tags            []string `json:"tags"`
	Version         string   `json:"version"`
	PlatformVersion string   `json:"platform_version"`
	Load1           float64  `json:"load_1"`
	Load5           float64  `json:"load_5"`
	Load15          float64  `json:"load_15"`
	CPUUsage        float64  `json:"cpu_usage"`
	MemUsage        float64  `json:"mem_usage"`
	TotalMem        int64    `json:"total_mem"`
	Nproc           int64    `json:"nproc"`
	HostSerial      string   `json:"host_serial"`
	HostID          string   `json:"host_id"`
	HostModel       string   `json:"host_model"`
	HostVendor      string   `json:"host_vendor"`
	CPUName         string   `json:"cpu_name"`
	DNS             string   `json:"dns"`
	Gateway         string   `json:"gateway"`
	StartTime       int64    `json:"start_time"`
	BootTime        int64    `json:"boot_time"`
	StateDetail     string   `json:"state_detail"`
}

func DescribeHostDetail(ctx *gin.Context) {
	if id := ctx.Query("agent_id"); id != "" {
		c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		res := c.FindOne(ctx, bson.M{"agent_id": id})
		info := asset_center.AgentDetailInfo{}
		err := res.Decode(&info)
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		now := time.Now()
		resp := DescribeHostDetailResp{}
		// mapping fields
		{
			resp.AgentID = info.AgentID
			resp.BootAt = info.BootTime
			resp.BootTime = info.BootTime
			resp.CPUName = info.CPUName
			resp.CPUUsage = info.CpuUsage
			resp.DNS = info.DNS
			resp.ExtranetIPv4 = info.ExtranetIPv4
			resp.ExtranetIPv6 = info.ExtranetIPv6
			resp.FirstHeartbeatTime = info.FirstHeartbeatTime
			resp.Gateway = info.Gateway
			resp.HostID = info.HostID
			resp.HostModel = info.HostModel
			resp.HostSerial = info.HostSerial
			resp.HostVendor = info.HostVendor
			resp.Hostname = info.Hostname
			resp.Idc = info.IDC
			resp.IntranetIPv4 = info.IntranetIPv4
			resp.IntranetIPv6 = info.IntranetIPv6
			resp.KernelVersion = info.KernelVersion
			resp.LastHeartbeatTime = info.LastHeartbeatTime
			resp.Load1 = info.Load1
			resp.Load15 = info.Load15
			resp.Load5 = info.Load5
			resp.MemUsage = info.MemUsage
			resp.NetMode = info.NetMode
			resp.Nproc = info.Nproc
			resp.Pid = info.Pid
			resp.Platform = info.Platform
			resp.PlatformVersion = info.PlatformVersion
			resp.StartTime = info.StartTime
			resp.StartedAt = info.StartedAt
			resp.Status = info.GetStatus(now)
			resp.StateDetail = info.StateDetail
			resp.Tags = info.Tags
			resp.TotalMem = info.TotalMem
			resp.Version = info.Version
		}
		for _, p := range info.Plugins {
			rp := DescribeHostDetailRespPluginItem{
				LastHeartbeatTime: p.LastHeartbeatTime,
				Name:              p.Name,
				Pversion:          p.Pversion,
				StartedAt:         p.StartedAt,
				StartTime:         p.StartTime,
				CPU:               p.CPU,
				Memory:            p.Memory,
			}
			if p.Status == "exited" || now.Unix()-p.LastHeartbeatTime > asset_center.DEFAULT_OFFLINE_DURATION {
				rp.Status = "exited"
			} else {
				rp.Status = "running"
			}
			resp.Plugins = append(resp.Plugins, rp)
		}
		// hids alarm
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
		cursor, err := c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"agent_id":       id,
					"__alarm_status": 0,
					"__checked":      true,
					"__hit_wl":       false,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$SMITH_ALERT_DATA.RULE_INFO.HarmLevel",
					"count": bson.M{
						"$sum": 1,
					},
				},
			},
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch level {
				case "critical":
					resp.Alarm.Critical = count
				case "high":
					resp.Alarm.High = count
				case "medium":
					resp.Alarm.Medium = count
				case "low":
					resp.Alarm.Low = count
				}
			}
		}
		// rasp alarm
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspAlarmCollectionV1)
		cursor, err = c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"agent_id":       id,
					"__alarm_status": 0,
					"__checked":      true,
					"__hit_wl":       false,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$HarmLevel",
					"count": bson.M{
						"$sum": 1,
					},
				},
			},
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch level {
				case "critical":
					resp.RaspAlarm.Critical = count
				case "high":
					resp.RaspAlarm.High = count
				case "medium":
					resp.RaspAlarm.Medium = count
				case "low":
					resp.RaspAlarm.Low = count
				}
			}
		}
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VirusDetectionCollectionV1)
		cursor, err = c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"agent_id":       id,
					"__alarm_status": 0,
					"__checked":      true,
					"__hit_wl":       false,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$SMITH_ALERT_DATA.RULE_INFO.HarmLevel",
					"count": bson.M{
						"$sum": 1,
					},
				},
			},
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch level {
				case "critical":
					resp.Virus.Critical = count
				case "high":
					resp.Virus.High = count
				case "medium":
					resp.Virus.Medium = count
				case "low":
					resp.Virus.Low = count
				}
			}
		}
		// hids event
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmEventCollectionV1)
		cursor, err = c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"hosts.agent_id": id,
					"status":         0,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$level",
					"count": bson.M{
						"$sum": 1,
					},
				},
			},
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch level {
				case "critical":
					resp.Event.Critical = count
				case "high":
					resp.Event.High = count
				case "medium":
					resp.Event.Medium = count
				case "low":
					resp.Event.Low = count
				}
			}
		}
		// rasp event
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspEventCollectionV1)
		cursor, err = c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"hosts.agent_id": id,
					"status":         0,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$level",
					"count": bson.M{
						"$sum": 1,
					},
				},
			},
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch level {
				case "critical":
					resp.RaspEvent.Critical = count
				case "high":
					resp.RaspEvent.High = count
				case "medium":
					resp.RaspEvent.Medium = count
				case "low":
					resp.RaspEvent.Low = count
				}
			}
		}
		// vul info
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
		cursor, err = c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"agent_id":    id,
					"status":      "unprocessed",
					"drop_status": "using",
					"action":      vuln.VulnActionBlock,
				},
			},
			bson.M{
				"$group": bson.M{
					"_id": "$level",
					"count": bson.M{
						"$sum": 1,
					},
				},
			},
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch level {
				case vuln.DangerLevel:
					resp.Vuln.Critical = count
				case vuln.HighLevel:
					resp.Vuln.High = count
				case vuln.MidLevel:
					resp.Vuln.Medium = count
				case vuln.LowLevel:
					resp.Vuln.Low = count
				}
			}
		}

		baselineTaskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
		cursor, err = baselineTaskStatusCol.Find(ctx, bson.M{"agent_id": id})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			var baselinetaskStatus baseline.BaselineTaskStatus
			err := cursor.Decode(&baselinetaskStatus)
			if err != nil {
				continue
			}
			resp.Baseline.High += baselinetaskStatus.HighRiskNum
			resp.Baseline.Medium += baselinetaskStatus.MediumRiskNum
			resp.Baseline.Low += baselinetaskStatus.LowRiskNum
			resp.Baseline.Pass += baselinetaskStatus.PassNum
		}
		CreateResponse(ctx, common.SuccessCode, resp)
	} else {
		ylog.Errorf("asset-center", "agent_id param is required")
		CreateResponse(ctx, common.ParamInvalidErrorCode, "agent_id param is required")
	}
}

type TagsReq struct {
	Tags           []string `json:"tags" bson:"tags" binding:"required,unique"`
	GeneralHostReq `json:",omitempty,inline"`
}

func AddTags(ctx *gin.Context) {
	req := TagsReq{}
	err := ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	_, err = c.UpdateMany(ctx, req.GenerateFilter(), bson.M{
		"$addToSet": bson.M{"tags": bson.M{"$each": req.Tags}},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, nil)
}
func DeleteTags(ctx *gin.Context) {
	req := TagsReq{}
	err := ctx.BindJSON(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	_, err = c.UpdateMany(ctx, req.GenerateFilter(), bson.M{
		"$pullAll": bson.M{"tags": req.Tags},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, nil)
}
func UpdateTags(ctx *gin.Context) {
	req := TagsReq{}
	err := ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	_, err = c.UpdateMany(ctx, req.GenerateFilter(), bson.M{
		"$set": bson.M{"tags": req.Tags},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, nil)
}
func DescribeTags(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	tags, err := c.Distinct(ctx, "tags", bson.M{})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, utils.MustBeStringSlice(tags))
}
func DescribePlatform(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	platform, err := c.Distinct(ctx, "platform", bson.M{})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, utils.MustBeStringSlice(platform))
}
func DescribeIDC(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	idc, err := c.Distinct(ctx, "idc", bson.M{})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, utils.MustBeStringSlice(idc))
}
func DescribeHostStatistics(c *gin.Context) {
	res, err := cronjob.GetLatestResult(c.FullPath())
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	} else {
		if len(res) == 0 {
			common.CreateResponse(c, common.SuccessCode, cronjob.DescribeAgentData{})
		} else {
			common.CreateResponse(c, common.SuccessCode, res)
		}
	}
}
func DescribeKernelVersion(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	res, err := c.Distinct(ctx, "kernel_version", bson.M{"kernel_version": bson.M{"$exists": true}})
	if err != nil {
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		common.CreateResponse(ctx, common.SuccessCode, res)
	}
}
func ExportHosts(ctx *gin.Context) {
	req := GeneralHostReq{}
	err := ctx.BindJSON(&req)
	if err != nil {
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}

	defs := common.MongoDBDefs{
		{"agent_id", "AgentID"},
		{"hostname", "Hostname"},
		{"intranet_ipv4", "IntranetIPv4"},
		{"extranet_ipv4", "ExtranetIPv4"},
		{"intranet_ipv6", "IntranetIPv6"},
		{"extranet_ipv6", "ExtranetIPv6"},
		{"idc", "IDC"},
		{"platform", "Platform"},
		{"cpu", "CPU"},
		{"rss", "RSS"},
		{"last_heartbeat_time", "LastHeartbeatTime"},
	}

	common.ExportFromMongoDB(
		ctx,
		infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection),
		req.GenerateFilter(),
		defs,
		"hosts",
	)
}
