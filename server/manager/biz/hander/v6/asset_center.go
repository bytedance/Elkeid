package v6

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"io"
	"math/rand"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
)

var UTC_OFFSET = "+0800"

func init() {
	UTC_OFFSET = strings.Fields(time.Now().String())[2]
}

const DEFAULT_OFFLINE_DURATION = 30 * 60
const DangerLevel = "danger"
const HighLevel = "high"
const MidLevel = "medium"
const LowLevel = "low"

type HostBasicInfo struct {
	AgentID           string   `json:"agent_id" bson:"agent_id"`
	ExtranetIPv4      []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	ExtranetIPv6      []string `json:"extranet_ipv6" bson:"extranet_ipv6"`
	IntranetIPv4      []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	IntranetIPv6      []string `json:"intranet_ipv6" bson:"intranet_ipv6"`
	Hostname          string   `json:"hostname" bson:"hostname"`
	IDC               string   `json:"idc" bson:"idc"`
	LastHeartbeatTime int64    `json:"last_heartbeat_time" bson:"last_heartbeat_time"`
	Platform          string   `json:"platform" bson:"platform"`
	Tags              []string `json:"tags" bson:"tags"`
	Risk              struct {
		Vuln  int `json:"vuln" bson:"vuln"`
		Alarm int `json:"alarm" bson:"alarm"`
	} `json:"risk" bson:"risk"`
	Status string `json:"status" bson:"status"`
}

func (d *HostBasicInfo) Normalize() {
	current := time.Now().Unix()
	if d.LastHeartbeatTime <= current-600 {
		d.Status = "offline"
	} else {
		d.Status = "running"
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
}

type HostDetail struct {
	AgentID            string   `json:"agent_id" bson:"agent_id"`
	BootAt             int64    `json:"boot_at" bson:"boot_at"`
	ExtranetIpv4       []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	ExtranetIpv6       []string `json:"extranet_ipv6" bson:"extranet_ipv6"`
	FirstHeartbeatTime int64    `json:"first_heartbeat_time" bson:"first_heartbeat_time"`
	Hostname           string   `json:"hostname" bson:"hostname"`
	Idc                string   `json:"idc" bson:"idc"`
	IntranetIpv4       []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	IntranetIpv6       []string `json:"intranet_ipv6" bson:"intranet_ipv6"`
	KernelVersion      string   `json:"kernel_version" bson:"kernel_version"`
	LastHeartbeatTime  int64    `json:"last_heartbeat_time" bson:"last_heartbeat_time"`
	Status             string   `json:"status" bson:"status"`
	NetMode            string   `json:"net_mode" bson:"net_mode"`
	Pid                int64    `json:"pid" bson:"pid"`
	Platform           string   `json:"platform" bson:"platform"`
	Config             []struct {
		Name    string `json:"name" bson:"name"`
		Type    string `json:"type" bson:"type"`
		Version string `json:"version" bson:"version"`
	} `json:"-" bson:"config"`
	Plugins []struct {
		LastHeartbeatTime int64  `json:"last_heartbeat_time" bson:"last_heartbeat_time"`
		Name              string `json:"name" bson:"name"`
		Type              string `json:"type" bson:"type"`
		Pid               int64  `json:"pid" bson:"pid"`
		Pversion          string `json:"pversion" bson:"pversion"`
		Status            string `json:"status" bson:"status"`
		StartedAt         int64  `json:"started_at" bson:"started_at"`
	} `json:"plugins" bson:"plugins"`
	Alarm struct {
		Critical int64 `json:"critical" bson:"critical"`
		High     int64 `json:"high" bson:"high"`
		Medium   int64 `json:"medium" bson:"medium"`
		Low      int64 `json:"low" bson:"low"`
	} `json:"alarm" bson:"alarm"`
	Vuln struct {
		Critical int64 `json:"critical" bson:"critical"`
		High     int64 `json:"high" bson:"high"`
		Medium   int64 `json:"medium" bson:"medium"`
		Low      int64 `json:"low" bson:"low"`
	} `json:"vuln" bson:"vuln"`
	StartedAt        int64    `json:"started_at" bson:"started_at"`
	Tags             []string `json:"tags" bson:"tags"`
	AssetFingerprint struct {
		Port     int64 `json:"port" bson:"port"`
		Process  int64 `json:"process" bson:"process"`
		User     int64 `json:"user" bson:"user"`
		Cron     int64 `json:"cron" bson:"cron"`
		Service  int64 `json:"service" bson:"service"`
		Software int64 `json:"software" bson:"software"`
	} `json:"asset_fingerprint" bson:"asset_fingerprint"`
	Version string `json:"version" bson:"version"`
}

func (d *HostDetail) Normalize() {
	current := time.Now().Unix()
	if d.LastHeartbeatTime <= current-600 {
		d.Status = "offline"
	} else {
		d.Status = "running"
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.Plugins == nil {
		d.Plugins = []struct {
			LastHeartbeatTime int64  `json:"last_heartbeat_time" bson:"last_heartbeat_time"`
			Name              string `json:"name" bson:"name"`
			Type              string `json:"type" bson:"type"`
			Pid               int64  `json:"pid" bson:"pid"`
			Pversion          string `json:"pversion" bson:"pversion"`
			Status            string `json:"status" bson:"status"`
			StartedAt         int64  `json:"started_at" bson:"started_at"`
		}{}
	}
}

type HostStatistics struct {
	Uninstalled int64 `json:"uninstalled" bson:"uninstalled"`
	Running     int64 `json:"running" bson:"running"`
	Abnormal    int64 `json:"abnormal" bson:"abnormal"`
	Offline     int64 `json:"offline" bson:"offline"`
	Alerted     int64 `json:"alerted" bson:"alerted"`
	Vulnerable  int64 `json:"vulnerable" bson:"vulnerable"`
	Total       int64 `json:"total" bson:"total"`
}

func TernaryStringSlice(statement bool, a, b []string) []string {
	if statement {
		return a
	}
	return b
}

func TernaryInt64(statement bool, a, b int64) int64 {
	if statement {
		return a
	}
	return b
}
func TernaryString(statement bool, a, b string) string {
	if statement {
		return a
	}
	return b
}
func TernaryInt(statement bool, a, b int) int {
	if statement {
		return a
	}
	return b
}
func Status2Cond(status string) (cond bson.M) {
	current := time.Now().Unix()
	switch status {
	case "running":
		cond = bson.M{"last_heartbeat_time": bson.M{"$gte": current - 600}}
	case "offline":
		cond = bson.M{"last_heartbeat_time": bson.M{"$lt": current - 600}}
	default:
		cond = bson.M{"last_heartbeat_time": cond}
	}
	return
}
func Risk2Cond(risk bool) (cond bson.M) {
	if risk {
		cond = bson.M{
			"$or": bson.A{
				bson.M{"risk.vuln": bson.M{"$ne": 0, "$exists": true}},
				bson.M{"risk.alarm": bson.M{"$ne": 0, "$exists": true}},
			},
		}
	} else {
		cond = bson.M{
			"$and": bson.A{
				bson.M{
					"$or": bson.A{bson.M{"risk.vuln": 0}, bson.M{"risk.vuln": bson.M{"$exists": false}}},
				},
				bson.M{
					"$or": bson.A{bson.M{"risk.alarm": 0}, bson.M{"risk.alarm": bson.M{"$exists": false}}},
				},
			},
		}
	}
	return
}

// Join ancond to cond.
func JoinCond(cond bson.M, ancond bson.M) {
	for k, v := range ancond {
		// 如果有相同的key，则合并到and中
		if i, ok := cond[k]; ok {
			// 两个key相同，但都不是$and
			if k != "$and" {
				// 如果原始cond有$and key，则判断$and key-value的类型
				if and, ok := cond["$and"]; ok {
					// append数组
					if and, ok := and.(bson.A); ok {
						cond["$and"] = append(and, i, v)
						// 新建数组，把原来的value的新增的value扔进数组中
					} else {
						cond["$and"] = bson.A{and, i, v}
					}
					// 如果原始cond没有$and key，则新建$and数组，并把两个条件扔进去
				} else {
					cond["$and"] = bson.A{i, v}
				}
				// 两个key都是$and
			} else {
				// 新的$and数组
				newAnd := bson.A{}
				// 如果$and key-value是数组，则append
				if and, ok := i.(bson.A); ok {
					newAnd = append(newAnd, and...)
					// 否则直接把$and key-value扔进去
				} else {
					newAnd = append(newAnd, i)
				}
				if and, ok := v.(bson.A); ok {
					newAnd = append(newAnd, and...)
				} else {
					newAnd = append(newAnd, v)
				}
				cond["$and"] = newAnd
			}
		}
		// 没有相同的，直接join
		cond[k] = v
	}
}

type FilterQuery map[string]interface{}

func (f FilterQuery) GenerateFingerprintBasicFilter(dataType string) (filter bson.M) {
	filter = bson.M{}
	for k, v := range f {
		if k == "agent_id" {
			filter[k] = v
			break
		}
	}
	filter["data_type"] = dataType
	return
}
func (f FilterQuery) GenerateFingerprintDetailFilter() (filter bson.M) {
	filter = bson.M{}
	for k, v := range f {
		if k == "agent_id" {
			continue
		}
		switch v := v.(type) {
		case string:
			if v != "" {
				filter["data."+k] = primitive.Regex{
					Pattern: "^" + regexp.QuoteMeta(v) + ".*",
					Options: ""}
			}
		default:
			filter["data."+k] = v
		}
	}
	return
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
	Risk     *bool    `json:"risk"`
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
			of = append(of, Status2Cond(v))
		}
		if orFilter, ok := m["$or"]; ok {
			m["$and"] = bson.A{
				bson.M{"$or": orFilter}, bson.M{"$or": of},
			}
		} else {
			m["$or"] = of
		}
	}
	if r.Risk != nil {
		c := Risk2Cond(*r.Risk)
		if of, ok := c["$or"]; ok {
			if orFilter, ok := m["$or"]; ok {
				m["$and"] = bson.A{
					bson.M{"$or": orFilter}, bson.M{"$or": of},
				}
			} else {
				m["$or"] = of
			}
		} else {
			JoinCond(m, c)
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

func DescribeHosts(ctx *gin.Context) {
	pq := &PageRequest{}
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
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
	preq := PageSearch{
		TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
		req.GenerateFilter(),
		bson.M{
			TernaryString(pq.OrderKey == "", "_id", pq.OrderKey): TernaryInt(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	data := []HostBasicInfo{}
	presp, err := DBSearchPaginate(c, preq, func(c *mongo.Cursor) (err error) {
		hb := HostBasicInfo{}
		err = c.Decode(&hb)
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			return
		} else {
			hb.Normalize()
			data = append(data, hb)
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
func DescribeHostDetail(ctx *gin.Context) {
	if id := ctx.Query("agent_id"); id != "" {
		c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		res := c.FindOne(ctx, bson.M{"agent_id": id})
		hd := HostDetail{}
		err := res.Decode(&hd)
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		hd.Normalize()
		current := time.Now().Unix()
		for index, p := range hd.Plugins {
			// for _, c := range hd.Config {
			// 	if p.Name == c.Name {
			// 		hd.Plugins[index].Type = TernaryString(c.Type == "", "exec", c.Type)
			// 	}
			// 	if current-p.LastHeartbeatTime > DEFAULT_OFFLINE_DURATION {
			// 		hd.Plugins[index].Status = "exited"
			// 	} else {
			// 		hd.Plugins[index].Status = "running"
			// 	}
			// }
			hd.Plugins[index].Type = "exec"
			if current-p.LastHeartbeatTime > DEFAULT_OFFLINE_DURATION {
				hd.Plugins[index].Status = "exited"
			} else {
				hd.Plugins[index].Status = "running"
			}
		}
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
		cursor, err := c.Find(ctx, bson.M{
			"agent_id": id,
		})
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
			return
		}
		for cursor.Next(ctx) {
			if dt, ok := cursor.Current.Lookup("data_type").StringValueOK(); ok {
				if data, ok := cursor.Current.Lookup("data").ArrayOK(); ok {
					if data, err := data.Values(); err == nil {
						switch dt {
						case "5000":
							hd.AssetFingerprint.Process = int64(len(data))
						case "5001":
							hd.AssetFingerprint.Port = int64(len(data))
						case "5002":
							hd.AssetFingerprint.User = int64(len(data))
						case "5003":
							hd.AssetFingerprint.Cron = int64(len(data))
						case "5004", "5005", "5006", "5011":
							hd.AssetFingerprint.Software += int64(len(data))
						case "5010":
							hd.AssetFingerprint.Service = int64(len(data))
						}
					}
				}
			}
		}
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
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
					"_id": "$SMITH_ALETR_DATA.RULE_INFO.HarmLevel",
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
					hd.Alarm.Critical = count
				case "high":
					hd.Alarm.High = count
				case "medium":
					hd.Alarm.Medium = count
				case "low":
					hd.Alarm.Low = count
				}
			}
		}
		c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
		cursor, err = c.Aggregate(ctx, bson.A{
			bson.M{
				"$match": bson.M{
					"agent_id": id,
					"status":   "unprocessed",
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
				case DangerLevel:
					hd.Vuln.Critical = count
				case HighLevel:
					hd.Vuln.High = count
				case MidLevel:
					hd.Vuln.Medium = count
				case LowLevel:
					hd.Vuln.Low = count
				}
			}
		}
		CreateResponse(ctx, common.SuccessCode, hd)
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
func ShouldBeStringSlice(iface []interface{}) []string {
	res := []string{}
	for _, i := range iface {
		if s, ok := i.(string); ok {
			res = append(res, s)
		}
	}
	return res
}
func DescribeTags(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	tags, err := c.Distinct(ctx, "tags", bson.M{})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}

	common.CreateResponse(ctx, common.SuccessCode, ShouldBeStringSlice(tags))
}
func DescribePlatform(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	platform, err := c.Distinct(ctx, "platform", bson.M{})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, ShouldBeStringSlice(platform))
}
func DescribeIDC(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	idc, err := c.Distinct(ctx, "idc", bson.M{})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	common.CreateResponse(ctx, common.SuccessCode, ShouldBeStringSlice(idc))
}
func DescribeHostStatistics(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	hs := HostStatistics{}
	var err error
	hs.Total, err = c.CountDocuments(ctx, bson.M{"agent_id": bson.M{"$exists": true}})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	hs.Running, err = c.CountDocuments(ctx, Status2Cond("running"))
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	hs.Offline, err = c.CountDocuments(ctx, Status2Cond("offline"))
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	hs.Vulnerable, err = c.CountDocuments(ctx, bson.M{"risk.vuln": bson.M{"$ne": 0, "$exists": true}})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	hs.Alerted, err = c.CountDocuments(ctx, bson.M{"risk.alarm": bson.M{"$ne": 0, "$exists": true}})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(ctx, common.SuccessCode, hs)
}

type DescribeHostPortReq struct {
	AgentID  string `json:"agent_id" binding:"required"`
	Sip      string `json:"sip"`
	Sport    *int64 `json:"sport"`
	UID      *int64 `json:"uid"`
	Username string `json:"username"`
	Pid      *int64 `json:"pid"`
	Cmdline  string `json:"cmdline"`
	Comm     string `json:"comm"`
	Type     *int64 `json:"type"`
}

func (r *DescribeHostPortReq) GenerateFilter() (bson.M, bson.M) {
	bm := bson.M{
		"agent_id":  r.AgentID,
		"data_type": "5001",
	}
	dm := bson.M{}
	if r.Username != "" {
		dm["data.username"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Username) + ".*",
			Options: "",
		}
	}
	if r.Comm != "" {
		dm["data.comm"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Comm) + ".*",
			Options: "",
		}
	}
	if r.Cmdline != "" {
		dm["data.cmdline"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Cmdline) + ".*",
			Options: "",
		}
	}
	if r.Sip != "" {
		dm["data.sip"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Sip) + ".*",
			Options: "",
		}
	}
	if r.Username != "" {
		dm["data.username"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Username) + ".*",
			Options: "",
		}
	}
	if r.Pid != nil {
		dm["data.pid"] = *r.Pid
	}
	if r.UID != nil {
		dm["data.uid"] = *r.UID
	}
	if r.Sport != nil {
		dm["data.sport"] = *r.Sport
	}
	if r.Type != nil {
		dm["data.type"] = *r.Type
	}
	return bm, dm
}

type HostPort struct {
	Sip      string `json:"sip"`
	Sport    int64  `json:"sport"`
	Family   int64  `json:"family"`
	UID      int64  `json:"uid"`
	Username string `json:"username"`
	Pid      int64  `json:"pid"`
	Cmdline  string `json:"cmdline"`
	Comm     string `json:"comm"`
	Type     int64  `json:"type"`
}
type DescribeHostPortResp struct {
	List       []HostPort `json:"list"`
	UpdateTime int64      `json:"update_time"`
}

func DescribeHostPort(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := DescribeHostPortReq{}
	err = ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	bm, dm := req.GenerateFilter()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}
	data := DescribeHostPortResp{}
	presp, err := DBAggregatePaginate(c, []interface{}{
		bson.M{"$match": bm},
		bson.M{"$unwind": "$data"},
		bson.M{"$match": dm},
	}, preq, func(c *mongo.Cursor) error {
		item := HostPort{}
		if err := c.Current.Lookup("data").Unmarshal(&item); err == nil {
			if updateTime, ok := c.Current.Lookup("leader_time").Int64OK(); ok {
				data.UpdateTime = updateTime
			}
			data.List = append(data.List, item)
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type DescribeHostProcessReq struct {
	AgentID  string `json:"agent_id" binding:"required"`
	PID      *int64 `json:"pid"`
	PPID     *int64 `json:"ppid"`
	Comm     string `json:"comm"`
	Cmdline  string `json:"cmdline"`
	Exe      string `json:"exe"`
	Session  *int64 `json:"session"`
	Tty      *int64 `json:"tty"`
	Cwd      string `json:"cwd"`
	UID      *int64 `json:"uid"`
	Username string `json:"username"`
}

func (r *DescribeHostProcessReq) GenerateFilter() (bson.M, bson.M) {
	bm := bson.M{
		"agent_id":  r.AgentID,
		"data_type": "5000",
	}
	dm := bson.M{}
	if r.Comm != "" {
		dm["data.comm"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Comm) + ".*",
			Options: "",
		}
	}
	if r.Cmdline != "" {
		dm["data.cmdline"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Cmdline) + ".*",
			Options: "",
		}
	}
	if r.Exe != "" {
		dm["data.exe"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Exe) + ".*",
			Options: "",
		}
	}
	if r.Cwd != "" {
		dm["data.cwd"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Cwd) + ".*",
			Options: "",
		}
	}
	if r.Username != "" {
		dm["data.username"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Username) + ".*",
			Options: "",
		}
	}
	if r.UID != nil {
		dm["data.uid"] = *r.UID
	}
	if r.PID != nil {
		dm["data.pid"] = *r.PID
	}
	if r.Tty != nil {
		dm["data.tty"] = *r.Tty
	}
	if r.Session != nil {
		dm["data.session"] = *r.Session
	}
	if r.PPID != nil {
		dm["data.ppid"] = *r.PPID
	}
	return bm, dm
}

type HostProcess struct {
	Pid       int64  `json:"pid" bson:"pid"`
	Ppid      int64  `json:"ppid" bson:"ppid"`
	Comm      string `json:"comm" bson:"comm"`
	Cmdline   string `json:"cmdline" bson:"cmdline"`
	Exe       string `json:"exe" bson:"exe"`
	Session   int64  `json:"session" bson:"session"`
	Tty       int64  `json:"tty" bson:"tty"`
	StartTime int64  `json:"start_time" bson:"start_time"`
	Cwd       string `json:"cwd" bson:"cwd"`
	Checksum  string `json:"checksum" bson:"checksum"`
	UID       int64  `json:"uid" bson:"uid"`
	Username  string `json:"username" bson:"username"`
}
type DescribeHostProcessResp struct {
	List       []HostProcess `json:"list"`
	UpdateTime int64         `json:"update_time"`
}

func DescribeHostProcess(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := DescribeHostProcessReq{}
	err = ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	bm, dm := req.GenerateFilter()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}
	data := DescribeHostProcessResp{}
	presp, err := DBAggregatePaginate(c, []interface{}{
		bson.M{"$match": bm},
		bson.M{"$unwind": "$data"},
		bson.M{"$match": dm},
	}, preq, func(c *mongo.Cursor) error {
		item := HostProcess{}
		if err := c.Current.Lookup("data").Unmarshal(&item); err == nil {
			if updateTime, ok := c.Current.Lookup("leader_time").Int64OK(); ok {
				data.UpdateTime = updateTime
			}
			data.List = append(data.List, item)
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type DescribeHostUserReq struct {
	UID       *int64 `json:"uid"`
	Username  string `json:"username"`
	GID       *int64 `json:"gid"`
	GroupName string `json:"group_name"`
	AgentID   string `json:"agent_id" binding:"required"`
}

func (r *DescribeHostUserReq) GenerateFilter() (bson.M, bson.M) {
	bm := bson.M{
		"agent_id":  r.AgentID,
		"data_type": "5002",
	}
	dm := bson.M{}
	if r.Username != "" {
		dm["data.username"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Username) + ".*",
			Options: "",
		}
	}
	if r.GroupName != "" {
		dm["data.group_name"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.GroupName) + ".*",
			Options: "",
		}
	}
	if r.UID != nil {
		dm["data.uid"] = *r.UID
	}
	if r.GID != nil {
		dm["data.gid"] = *r.GID
	}
	return bm, dm
}

type HostUser struct {
	Username      string `json:"username" bson:"username"`
	UID           int64  `json:"uid" bson:"uid"`
	Gid           int64  `json:"gid" bson:"gid"`
	GroupName     string `json:"group_name" bson:"group_name"`
	Info          string `json:"info" bson:"info"`
	HomeDir       string `json:"home_dir" bson:"home_dir"`
	Shell         string `json:"shell" bson:"shell"`
	LastLoginTime int64  `json:"last_login_time" bson:"last_login_time"`
	LastLoginIP   string `json:"last_login_ip" bson:"last_login_ip"`
}
type DescribeHostUserResp struct {
	UpdateTime int64      `json:"update_time" bson:"update_time"`
	List       []HostUser `json:"list" bson:"list"`
}

func DescribeHostUser(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := DescribeHostUserReq{}
	err = ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	bm, dm := req.GenerateFilter()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}
	data := DescribeHostUserResp{}
	presp, err := DBAggregatePaginate(c, []interface{}{
		bson.M{"$match": bm},
		bson.M{"$unwind": "$data"},
		bson.M{"$match": dm},
	}, preq, func(c *mongo.Cursor) error {
		item := HostUser{}
		if err := c.Current.Lookup("data").Unmarshal(&item); err == nil {
			if updateTime, ok := c.Current.Lookup("leader_time").Int64OK(); ok {
				data.UpdateTime = updateTime
			}
			data.List = append(data.List, item)
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type DescribeHostServiceReq struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Command          string `json:"command"`
	WorkingDirectory string `json:"working_directory"`
	Restart          *bool  `json:"restart"`
	AgentID          string `json:"agent_id" binding:"required"`
}

func (r *DescribeHostServiceReq) GenerateFilter() (bson.M, bson.M) {
	bm := bson.M{
		"agent_id":  r.AgentID,
		"data_type": "5010",
	}
	dm := bson.M{}
	if r.Name != "" {
		dm["data.name"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Name) + ".*",
			Options: "",
		}
	}
	if r.Type != "" {
		dm["data.type"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Type) + ".*",
			Options: "",
		}
	}
	if r.Command != "" {
		dm["data.command"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Command) + ".*",
			Options: "",
		}
	}
	if r.WorkingDirectory != "" {
		dm["data.working_directory"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.WorkingDirectory) + ".*",
			Options: "",
		}
	}
	if r.Restart != nil {
		dm["data.restart"] = *r.Restart
	}
	return bm, dm
}

type HostService struct {
	Name             string `json:"name" bson:"name"`
	Type             string `json:"type" bson:"type"`
	Command          string `json:"command" bson:"command"`
	WorkingDirectory string `json:"working_directory" bson:"working_directory"`
	Checksum         string `json:"checksum" bson:"checksum"`
	Restart          bool   `json:"restart" bson:"restart"`
}
type DescribeHostServiceResp struct {
	UpdateTime int64         `json:"update_time" bson:"update_time"`
	List       []HostService `json:"list" bson:"list"`
}

func DescribeHostService(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := DescribeHostServiceReq{}
	err = ctx.Bind(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	bm, dm := req.GenerateFilter()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}
	data := DescribeHostServiceResp{}
	presp, err := DBAggregatePaginate(c, []interface{}{
		bson.M{"$match": bm},
		bson.M{"$unwind": "$data"},
		bson.M{"$match": dm},
	}, preq, func(c *mongo.Cursor) error {
		item := HostService{}
		if err := c.Current.Lookup("data").Unmarshal(&item); err == nil {
			if updateTime, ok := c.Current.Lookup("leader_time").Int64OK(); ok {
				data.UpdateTime = updateTime
			}
			data.List = append(data.List, item)
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type DescribeHostCronReq struct {
	Path     string `json:"path"`
	Username string `json:"username"`
	Command  string `json:"command"`
	AgentID  string `json:"agent_id" binding:"required"`
}

func (r *DescribeHostCronReq) GenerateFilter() (bson.M, bson.M) {
	bm := bson.M{
		"agent_id":  r.AgentID,
		"data_type": "5003",
	}
	dm := bson.M{}
	if r.Path != "" {
		dm["data.path"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Path) + ".*",
			Options: "",
		}
	}
	if r.Username != "" {
		dm["data.username"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Username) + ".*",
			Options: "",
		}
	}
	if r.Command != "" {
		dm["data.command"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Command) + ".*",
			Options: "",
		}
	}
	return bm, dm
}

type HostCron struct {
	Path     string `json:"path"`
	Schedule string `json:"schedule"`
	Username string `json:"username"`
	Command  string `json:"command"`
	Runparts string `json:"runparts"`
	Checksum string `json:"checksum"`
}
type DescribeHostCronResp struct {
	UpdateTime int64      `json:"update_time" bson:"update_time"`
	List       []HostCron `json:"list"`
}

func DescribeHostCron(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := DescribeHostCronReq{}
	err = ctx.BindJSON(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	bm, dm := req.GenerateFilter()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}
	data := DescribeHostCronResp{}
	presp, err := DBAggregatePaginate(c, []interface{}{
		bson.M{"$match": bm},
		bson.M{"$unwind": "$data"},
		bson.M{"$match": dm},
	}, preq, func(c *mongo.Cursor) error {
		item := HostCron{}
		if err := c.Current.Lookup("data").Unmarshal(&item); err == nil {
			if updateTime, ok := c.Current.Lookup("leader_time").Int64OK(); ok {
				data.UpdateTime = updateTime
			}
			data.List = append(data.List, item)
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type DescribeHostSoftwareReq struct {
	AgentID string `json:"agent_id" binding:"required"`
	Name    string `json:"name" bson:"name"`
	Version string `json:"version" bson:"version"`
	Type    string `json:"type" binding:"omitempty,oneof=pypi dpkg rpm jar"`
}

func (r *DescribeHostSoftwareReq) GenerateFilter() (bson.M, bson.M) {
	bm := bson.M{
		"agent_id": r.AgentID,
	}
	switch r.Type {
	case "dpkg":
		bm["data_type"] = "5004"
	case "rpm":
		bm["data_type"] = "5005"
	case "pypi":
		bm["data_type"] = "5006"
	case "jar":
		bm["data_type"] = "5011"
	default:
		bm["data_type"] = bson.M{"$in": bson.A{"5004", "5005", "5006", "5011"}}
	}
	dm := bson.M{}
	if r.Name != "" {
		dm["data.name"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Name) + ".*",
			Options: "",
		}
	}
	if r.Version != "" {
		dm["data.version"] = primitive.Regex{
			Pattern: "^" + regexp.QuoteMeta(r.Version) + ".*",
			Options: "",
		}
	}
	return bm, dm
}

type HostSoftware struct {
	Type    string `json:"type" bson:"type"`
	Version string `json:"version" bson:"version"`
	Name    string `json:"name" bson:"name"`
}
type DescribeHostSoftwareResp struct {
	UpdateTime int64          `json:"update_time" bson:"update_time"`
	List       []HostSoftware `json:"list"`
}

func DescribeHostSoftware(ctx *gin.Context) {
	pq := PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	req := DescribeHostSoftwareReq{}
	err = ctx.ShouldBindJSON(&req)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}
	bm, dm := req.GenerateFilter()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAssetCollectionV1)
	preq := PageSearch{
		Page:     TernaryInt64(pq.Page == 0, DefaultPage, pq.Page),
		PageSize: TernaryInt64(pq.PageSize == 0, DefaultPageSize, pq.PageSize),
	}
	data := DescribeHostSoftwareResp{}
	presp, err := DBAggregatePaginate(c, []interface{}{
		bson.M{"$match": bm},
		bson.M{"$unwind": "$data"},
		bson.M{"$match": dm},
	}, preq, func(c *mongo.Cursor) error {
		item := HostSoftware{}
		if err := c.Current.Lookup("data").Unmarshal(&item); err == nil {
			if dt, ok := c.Current.Lookup("data_type").StringValueOK(); ok {
				if dt == "5004" {
					item.Type = "dpkg"
				} else if dt == "5005" {
					item.Type = "rpm"
				} else if dt == "5006" {
					item.Type = "pypi"
				} else if dt == "5011" {
					item.Type = "jar"
				}
			}
			if updateTime, ok := c.Current.Lookup("leader_time").Int64OK(); ok {
				data.UpdateTime = updateTime
			}
			data.List = append(data.List, item)
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *presp)
	}
}

type ExportProgress struct {
	ExportTotal int64 `json:"export_total"`
	ExportCount int64 `json:"export_count"`
	//init exporting saving success failed
	Status   string `json:"status"`
	FileName string `json:"file_name"`
}
type ExportHostsResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data *ExportProgress `json:"data"`
}

var Titles = []string{
	"AgentID", "Hostname", "IntranetIPv4",
	"IntranetIPv6", "ExtranetIPv4", "ExtranetIPv6",
	"Platform", "PlatformFamily", "PlatformVersion",
	"NetMode", "IDC", "Region",
}
var Fields = []string{
	"agent_id", "hostname", "intranet_ipv4",
	"intranet_ipv6", "extranet_ipv4", "extranet_ipv6",
	"platform", "platform_family", "platform_version",
	"net_mode", "idc", "region",
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandStringBytesMaskImprSrcSB(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}
func ExportHosts(ctx *gin.Context) {
	mu := sync.Mutex{}
	filename := "Exported-Hosts" + "-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + RandStringBytesMaskImprSrcSB(8) + ".zip"
	resp := ExportHostsResp{
		Data: &ExportProgress{
			Status:   "init",
			FileName: filename,
		},
	}
	req := GeneralHostReq{}
	ticker := time.NewTicker(time.Second)
	done := make(chan error)
	go func() {
		defer ticker.Stop()
		defer close(done)
		err := ctx.BindJSON(&req)
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		resp.Data.ExportTotal, err = c.CountDocuments(context.Background(), req.GenerateFilter())
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		cursor, err := c.Find(context.Background(), req.GenerateFilter())
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		bucket, err := gridfs.NewBucket(infra.MongoClient.Database(infra.MongoDatabase))
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		stream, err := bucket.OpenUploadStream(filename)
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		ziper := zip.NewWriter(stream)
		file, err := ziper.Create(path.Base(filename)[:len(filename)-3] + "csv")
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		csver := csv.NewWriter(file)
		err = csver.Write(Titles)
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		mu.Lock()
		resp.Data.Status = "exporting"
		resp.Data.FileName = filename
		mu.Unlock()
		for cursor.Next(context.Background()) {
			record := []string{}
			for _, f := range Fields {
				item := ""
				rv := cursor.Current.Lookup(f)
				if v, ok := rv.StringValueOK(); ok {
					item = v
				} else if arr, ok := rv.ArrayOK(); ok {
					if vs, err := arr.Values(); err == nil {
						for _, v := range vs {
							if i, ok := v.StringValueOK(); ok {
								if item != "" {
									item = item + "," + i
								} else {
									item = i
								}
							}
						}
					}

				} else if v, ok := rv.DoubleOK(); ok {
					item = strconv.FormatFloat(v, 'f', -1, 64)
				} else if v, ok := rv.AsInt64OK(); ok {
					item = strconv.FormatInt(v, 10)
				}
				record = append(record, item)
			}
			err = csver.Write(record)
			if err != nil {
				ylog.Errorf("asset-center", err.Error())
				done <- err
				return
			}
			mu.Lock()
			resp.Data.ExportCount++
			mu.Unlock()
		}
		mu.Lock()
		resp.Data.Status = "saving"
		mu.Unlock()
		csver.Flush()
		err = ziper.Close()
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
		err = stream.Close()
		if err != nil {
			ylog.Errorf("asset-center", err.Error())
			done <- err
			return
		}
	}()
	ctx.Stream(func(w io.Writer) bool {
		select {
		case <-ticker.C:
			mu.Lock()
			defer mu.Unlock()
			resp.Code = common.SuccessCode
			resp.Msg = "success"
			ctx.SSEvent("progress", resp)
			return true
		case err, ok := <-done:
			mu.Lock()
			defer mu.Unlock()
			if ok {
				resp.Code = common.UnknownErrorCode
				resp.Msg = "export failed, " + err.Error()
				resp.Data.Status = "failed"
			} else {
				resp.Code = common.SuccessCode
				resp.Msg = "success"
				resp.Data.Status = "success"
				resp.Data.ExportCount = resp.Data.ExportTotal
			}
			ctx.SSEvent("progress", resp)
			return false
		}
	})
}
func DescribeHostPlatformStatistics(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := c.Aggregate(ctx, bson.A{
		bson.M{"$group": bson.M{
			"_id": "$platform",
			"count": bson.M{
				"$sum": 1,
			},
		}},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	resp := []map[string]interface{}{}
	for cursor.Next(ctx) {
		if platform, ok := cursor.Current.Lookup("_id").StringValueOK(); ok {
			if count, ok := cursor.Current.Lookup("count").AsInt64OK(); ok {
				resp = append(resp, map[string]interface{}{
					"platform": platform,
					"count":    count,
				})
			}
		}
	}
	common.CreateResponse(ctx, common.SuccessCode, resp)
}
func DescribeAgentVersionStatistics(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := c.Aggregate(ctx, bson.A{
		bson.M{"$group": bson.M{
			"_id": "$version",
			"count": bson.M{
				"$sum": 1,
			},
		}},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	resp := []map[string]interface{}{}
	for cursor.Next(ctx) {
		if version, ok := cursor.Current.Lookup("_id").StringValueOK(); ok {
			if count, ok := cursor.Current.Lookup("count").AsInt64OK(); ok {
				resp = append(resp, map[string]interface{}{
					"version": version,
					"count":   count,
				})
			}
		}
	}
	common.CreateResponse(ctx, common.SuccessCode, resp)
}

type DescribeTop10VulnHostsResp struct {
	AgentID  string `json:"agent_id" bson:"agent_id"`
	Hostname string `json:"hostname" bson:"hostname"`
	Vulns    int64  `json:"vulns" bson:"vulns"`
}

func DescribeTop10VulnHosts(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := c.Aggregate(ctx, bson.A{
		bson.M{"$match": bson.M{
			"risk.vuln": bson.M{"$ne": 0, "$exists": true},
		}},
		bson.M{"$sort": bson.M{
			"risk.vuln": -1,
		}},
		bson.M{"$limit": 10},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	}
	resp := []DescribeTop10VulnHostsResp{}
	for cursor.Next(ctx) {
		item := DescribeTop10VulnHostsResp{}
		err := cursor.Decode(&item)
		if err == nil {
			if risk, ok := cursor.Current.Lookup("risk").DocumentOK(); ok {
				item.Vulns, _ = risk.Lookup("vuln").AsInt64OK()
			}
			resp = append(resp, item)
		}
	}
	common.CreateResponse(ctx, common.SuccessCode, resp)
}

type DescribeTop10AlarmHostsResp struct {
	AgentID  string `json:"agent_id" bson:"agent_id"`
	Hostname string `json:"hostname" bson:"hostname"`
	Alarms   int64  `json:"alarms" bson:"alarms"`
}

func DescribeTop10AlarmHosts(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := c.Aggregate(ctx, bson.A{
		bson.M{"$match": bson.M{
			"risk.alarm": bson.M{"$ne": 0, "$exists": true},
		}},
		bson.M{"$sort": bson.M{
			"risk.alarm": -1,
		}},
		bson.M{"$limit": 10},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	resp := []DescribeTop10AlarmHostsResp{}
	for cursor.Next(ctx) {
		item := DescribeTop10AlarmHostsResp{}
		err := cursor.Decode(&item)
		if err == nil {
			if risk, ok := cursor.Current.Lookup("risk").DocumentOK(); ok {
				item.Alarms, _ = risk.Lookup("alarm").AsInt64OK()
			}
			resp = append(resp, item)
		}
	}
	common.CreateResponse(ctx, common.SuccessCode, resp)
}

type DescribeLast7DaysAlarmStatisticsResp struct {
	Date     int64 `json:"date"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
}

func DescribeLast7DaysAlarmStatistics(ctx *gin.Context) {
	_, offset := time.Now().Zone()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	cursor, err := c.Aggregate(ctx,
		bson.A{
			bson.M{
				"$match": bson.M{
					"__insert_time": bson.M{
						"$gt": time.Now().
							AddDate(0, 0, -6).
							Truncate(time.Hour * 24).
							Add(-time.Duration(offset) * time.Second).
							Unix(),
					},
					"__hit_wl": false, "__checked": true,
				},
			},
			bson.M{
				"$project": bson.M{
					"date": bson.M{"$toDate": bson.M{
						"$multiply": bson.A{"$__insert_time", 1000},
					}},
					"risk": "$SMITH_ALETR_DATA.RULE_INFO.HarmLevel",
				}},
			bson.M{"$group": bson.M{
				"_id": bson.M{
					"month": bson.M{"$month": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"day":   bson.M{"$dayOfMonth": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"year":  bson.M{"$year": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"risk":  "$risk",
				},
				"count": bson.M{
					"$sum": 1,
				},
			}},
		},
	)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	resp := []DescribeLast7DaysAlarmStatisticsResp{}
	for cursor.Next(ctx) {
		group := cursor.Current.Lookup("_id").Document()
		date := time.Date(int(group.Lookup("year").AsInt64()),
			time.Month(group.Lookup("month").AsInt64()),
			int(group.Lookup("day").AsInt64()), 0, 0, 0, 0, time.Local).Unix()
		flag := false
		for index, v := range resp {
			if v.Date == date {
				switch group.Lookup("risk").StringValue() {
				case "low":
					v.Low = cursor.Current.Lookup("count").AsInt64()
				case "medium":
					v.Medium = cursor.Current.Lookup("count").AsInt64()
				case "high":
					v.High = cursor.Current.Lookup("count").AsInt64()
				case "critical":
					v.Critical = cursor.Current.Lookup("count").AsInt64()
				}
				resp[index] = v
				flag = true
				break
			}
		}
		if !flag {
			v := DescribeLast7DaysAlarmStatisticsResp{
				Date: date,
			}
			switch group.Lookup("risk").StringValue() {
			case "low":
				v.Low = cursor.Current.Lookup("count").AsInt64()
			case "medium":
				v.Medium = cursor.Current.Lookup("count").AsInt64()
			case "high":
				v.High = cursor.Current.Lookup("count").AsInt64()
			case "critical":
				v.Critical = cursor.Current.Lookup("count").AsInt64()
			}
			resp = append(resp, v)
		}

	}
	sort.Slice(resp, func(i int, j int) bool {
		return resp[i].Date < resp[j].Date
	})
	common.CreateResponse(ctx, common.SuccessCode, resp)
}

type DescribeLast7DaysVulnStatisticsResp struct {
	Date     int64 `json:"date"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
}

func DescribeLast7DaysVulnStatistics(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	_, offset := time.Now().Zone()
	cursor, err := c.Aggregate(ctx,
		bson.A{
			bson.M{
				"$match": bson.M{
					"create_time": bson.M{
						"$gt": time.Now().
							AddDate(0, 0, -6).
							Truncate(time.Hour * 24).
							Add(-time.Duration(offset) * time.Second).
							Unix(),
					}},
			},
			bson.M{
				"$project": bson.M{
					"date": bson.M{"$toDate": bson.M{
						"$multiply": bson.A{"$create_time", 1000},
					}},
					"risk": "$level",
				}},
			bson.M{"$group": bson.M{
				"_id": bson.M{
					"month": bson.M{"$month": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"day":   bson.M{"$dayOfMonth": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"year":  bson.M{"$year": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"risk":  "$risk",
				},
				"count": bson.M{
					"$sum": 1,
				},
			}},
		},
	)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	resp := []DescribeLast7DaysVulnStatisticsResp{}
	for cursor.Next(ctx) {
		group := cursor.Current.Lookup("_id").Document()
		date := time.Date(int(group.Lookup("year").AsInt64()),
			time.Month(group.Lookup("month").AsInt64()),
			int(group.Lookup("day").AsInt64()), 0, 0, 0, 0, time.Local).Unix()
		flag := false
		for index, v := range resp {
			if v.Date == date {
				risk, ok1 := group.Lookup("risk").StringValueOK()
				count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
				if ok1 && ok2 {
					switch risk {
					case DangerLevel:
						v.Critical = count
					case HighLevel:
						v.High = count
					case MidLevel:
						v.Medium = count
					case LowLevel:
						v.Low = count
					}
				}
				resp[index] = v
				flag = true
				break
			}
		}
		if !flag {
			v := DescribeLast7DaysVulnStatisticsResp{
				Date: date,
			}
			risk, ok1 := group.Lookup("risk").StringValueOK()
			count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
			if ok1 && ok2 {
				switch risk {
				case DangerLevel:
					v.Critical = count
				case HighLevel:
					v.High = count
				case MidLevel:
					v.Medium = count
				case LowLevel:
					v.Low = count
				}
			}
			resp = append(resp, v)
		}

	}
	sort.Slice(resp, func(i int, j int) bool {
		return resp[i].Date < resp[j].Date
	})
	common.CreateResponse(ctx, common.SuccessCode, resp)
}

type DescribeLast7DaysOperationStatisticsResp struct {
	Date   int64 `json:"date"`
	Alarms int64 `json:"alarms"`
	Vulns  int64 `json:"vulns"`
}

func DescribeLast7DaysOperationStatistics(ctx *gin.Context) {
	_, offset := time.Now().Zone()
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	cursor, err := c.Aggregate(ctx,
		bson.A{
			bson.M{
				"$match": bson.M{
					"control_time": bson.M{"$gt": time.Now().AddDate(0, 0, -6).Truncate(time.Hour * 24).Add(-time.Duration(offset) * time.Second).Unix()},
					"status":       bson.M{"$ne": "unprocessed"},
				},
			},
			bson.M{
				"$project": bson.M{
					"date": bson.M{"$toDate": bson.M{
						"$multiply": bson.A{"$control_time", 1000},
					}},
				}},
			bson.M{"$group": bson.M{
				"_id": bson.M{
					"month": bson.M{"$month": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"day":   bson.M{"$dayOfMonth": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
					"year":  bson.M{"$year": bson.M{"date": "$date", "timezone": UTC_OFFSET}},
				},
				"count": bson.M{
					"$sum": 1,
				},
			}},
		},
	)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	resp := []DescribeLast7DaysOperationStatisticsResp{}
	for cursor.Next(ctx) {
		group := cursor.Current.Lookup("_id").Document()
		date := time.Date(int(group.Lookup("year").AsInt64()),
			time.Month(group.Lookup("month").AsInt64()),
			int(group.Lookup("day").AsInt64()), 0, 0, 0, 0, time.Local).Unix()
		flag := false
		for index, v := range resp {
			if v.Date == date {
				if count, ok := cursor.Current.Lookup("count").AsInt64OK(); ok {
					v.Vulns = count
					resp[index] = v
					flag = true
					break
				}
			}
		}
		if !flag {
			v := DescribeLast7DaysOperationStatisticsResp{
				Date: date,
			}
			if count, ok := cursor.Current.Lookup("count").AsInt64OK(); ok {
				v.Vulns = count
			}
			resp = append(resp, v)
		}
	}
	c = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1)
	cursor, err = c.Aggregate(ctx,
		bson.A{
			bson.M{
				"$match": bson.M{
					"__update_time": bson.M{
						"$gt": time.Now().
							AddDate(0, 0, -6).
							Truncate(time.Hour * 24).
							Add(-time.Duration(offset) * time.Second).
							Unix()},
					"__alarm_status": bson.M{"$ne": 0},
					"__hit_wl":       false,
					"__checked":      true,
				},
			},
			bson.M{
				"$project": bson.M{
					"date": bson.M{"$toDate": bson.M{
						"$multiply": bson.A{"$__update_time", 1000},
					}},
				}},
			bson.M{"$group": bson.M{
				"_id": bson.M{
					"month": bson.M{"$month": "$date"},
					"day":   bson.M{"$dayOfMonth": "$date"},
					"year":  bson.M{"$year": "$date"},
				},
				"count": bson.M{
					"$sum": 1,
				},
			}},
		},
	)
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
		return
	}
	for cursor.Next(ctx) {
		group := cursor.Current.Lookup("_id").Document()
		date := time.Date(int(group.Lookup("year").AsInt64()),
			time.Month(group.Lookup("month").AsInt64()),
			int(group.Lookup("day").AsInt64()), 0, 0, 0, 0, time.Local).Unix()
		flag := false
		for index, v := range resp {
			if v.Date == date {
				if count, ok := cursor.Current.Lookup("count").AsInt64OK(); ok {
					v.Alarms = count
					resp[index] = v
					flag = true
					break
				}
			}
		}
		if !flag {
			v := DescribeLast7DaysOperationStatisticsResp{
				Date: date,
			}
			if count, ok := cursor.Current.Lookup("count").AsInt64OK(); ok {
				v.Alarms = count
			}
			resp = append(resp, v)
		}
	}
	sort.Slice(resp, func(i int, j int) bool {
		return resp[i].Date < resp[j].Date
	})
	common.CreateResponse(ctx, common.SuccessCode, resp)
}

func DescribeKernelVersion(ctx *gin.Context) {
	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	res, err := c.Distinct(ctx, "kernel_version", bson.M{"kernel_version": bson.M{"$exists": true}})
	if err != nil {
		common.CreateResponse(ctx, common.DBOperateErrorCode, "")
	} else {
		common.CreateResponse(ctx, common.SuccessCode, res)
	}
}
