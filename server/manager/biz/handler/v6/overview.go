package v6

import (
	"context"
	"sort"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/baseline"
	"github.com/bytedance/Elkeid/server/manager/internal/cronjob"
	"github.com/bytedance/Elkeid/server/manager/internal/vuln"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

type HostStatistics struct {
	Uninstalled int64 `json:"uninstalled" bson:"uninstalled"`
	Running     int64 `json:"running" bson:"running"`
	Abnormal    int64 `json:"abnormal" bson:"abnormal"`
	Offline     int64 `json:"offline" bson:"offline"`
	Alerted     int64 `json:"alerted" bson:"alerted"`
	Vulnerable  int64 `json:"vulnerable" bson:"vulnerable"`
	Baseline    int64 `json:"baseline" bson:"baseline"`
	Total       int64 `json:"total" bson:"total"`
}

func DescribeAgent(c *gin.Context) {
	res, err := cronjob.GetLatestResult(c.FullPath())
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	} else {
		if len(res) == 0 {
			common.CreateResponse(c, common.SuccessCode, HostStatistics{})
		} else {
			common.CreateResponse(c, common.SuccessCode, res)
		}
	}
}
func DescribeAsset(c *gin.Context) {
	m, err := cronjob.GetLatestResult(c.FullPath())
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	common.CreateResponse(c, common.SuccessCode, m)
}

// 漏洞风险统计
func VulnRisk(c *gin.Context) {
	type Response struct {
		Low         int              `json:"low"`
		Mid         int              `json:"mid"`
		High        int              `json:"high"`
		Danger      int              `json:"danger"`
		UnProcessed int              `json:"unprocessed"`
		HotPatch    int              `json:"hot_patch"`
		UpdateTime  int64            `json:"update_time"`
		Day7List    []vuln.VulnDaily `json:"7day_list" bson:"7day_list"`
	}
	var response Response
	vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)
	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)
	cur, _ := vulnHeartCol.Find(c, bson.M{"action": vuln.VulnActionBlock})
	for cur.Next(c) {
		var vulnHeart vuln.VulnHeart
		err := cur.Decode(&vulnHeart)
		if err != nil {
			continue
		}
		switch vulnHeart.Level {
		case vuln.LowLevel:
			response.Low++
		case vuln.MidLevel:
			response.Mid++
		case vuln.HighLevel:
			response.High++
		case vuln.DangerLevel:
			response.Danger++
		}
		if vulnHeart.InfectStatus.UnProcessed > 0 {
			response.UnProcessed++
		}
	}
	var vulnConfUpdate vuln.VulnConfUpdate
	err := vulnConfCol.FindOne(c, bson.M{"type": vuln.VulnConfAutoUpdate}).Decode(&vulnConfUpdate)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	response.UpdateTime = vulnConfUpdate.VulnLibVersion
	var vulnConf7day vuln.VulnConf7Day
	err = vulnConfCol.FindOne(c, bson.M{"type": vuln.VulnConf7DayList}).Decode(&vulnConf7day)
	response.Day7List = []vuln.VulnDaily{}
	if err != nil {
		ylog.Infof("Find error", err.Error())
	} else {
		// 逆序
		length := len(vulnConf7day.Day7List)
		if length > 7 {
			length = 7
		}
		for i := length - 1; i > 0; i-- {
			response.Day7List = append(response.Day7List, vulnConf7day.Day7List[i])
		}
	}

	response.Day7List = append(response.Day7List, vuln.VulnDaily{
		Date:    time.Now().Unix(),
		VulnNum: int64(response.UnProcessed),
	})

	common.CreateResponse(c, common.SuccessCode, response)
}

// 基线风险统计
func BaselineRisk(c *gin.Context) {
	type Response struct {
		Low          int    `json:"low"`
		Mid          int    `json:"mid"`
		High         int    `json:"high"`
		Total        int    `json:"total"`
		Score        int    `json:"score"`
		BaselineName string `json:"baseline_name"`
	}
	responseList := make([]Response, 0)
	aggregateSearchList := make(bson.A, 0)

	// 获取基线和名字对应关系
	baselineNameMap := make(map[int]Response, 0)
	baselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
	cur, _ := baselineCol.Find(c, bson.M{})
	for cur.Next(c) {
		var response Response
		var baselineInfo baseline.BaselineInfo
		err := cur.Decode(&baselineInfo)
		if err != nil {
			continue
		}
		response.BaselineName = baselineInfo.BaselineName
		baselineNameMap[baselineInfo.BaselineId] = response
	}

	// 获取统计信息
	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	aggregateSearchList = append(aggregateSearchList, bson.M{"$group": bson.M{
		"_id":        bson.M{"baseline_id": "$baseline_id", "check_level": "$check_level", "status": "$status"},
		"infect_num": bson.M{"$sum": 1},
	}})
	cur, _ = agentBaseCol.Aggregate(c, aggregateSearchList)
	for cur.Next(c) {
		tmpS := struct {
			Id struct {
				BaselineId int    `json:"baseline_id" bson:"baseline_id"`
				CheckLevel string `json:"check_level" bson:"check_level"`
				Status     string `json:"status" bson:"status"`
			} `json:"id" bson:"_id"`
			InfectNum int `json:"infect_num" bson:"infect_num"`
		}{}
		err := cur.Decode(&tmpS)
		if err != nil {
			continue
		}
		if _, ok := baselineNameMap[tmpS.Id.BaselineId]; ok {
			tmpResponse := baselineNameMap[tmpS.Id.BaselineId]
			if tmpS.Id.Status == "passed" {
				tmpResponse.Total += tmpS.InfectNum
			} else if tmpS.Id.Status == "failed" {
				tmpResponse.Total += tmpS.InfectNum
				tmpResponse.Score += tmpS.InfectNum
				switch tmpS.Id.CheckLevel {
				case baseline.BaselineCheckHigh:
					tmpResponse.High += tmpS.InfectNum
				case baseline.BaselineCheckMid:
					tmpResponse.Mid += tmpS.InfectNum
				case baseline.BaselineCheckLow:
					tmpResponse.Low += tmpS.InfectNum
				}
			}
			baselineNameMap[tmpS.Id.BaselineId] = tmpResponse
		}
	}
	for _, response := range baselineNameMap {
		responseList = append(responseList, response)
	}

	sort.Slice(responseList, func(i int, j int) bool {
		return responseList[i].Score > responseList[j].Score
	})
	responseList = responseList[:3]

	common.CreateResponse(c, common.SuccessCode, responseList)
}

// 主机风险分布
func AgentRisk(c *gin.Context) {
	type Response struct {
		Alarm    int64 `json:"alarm" bson:"alarm"`
		Vuln     int64 `json:"vuln" bson:"vuln"`
		Baseline int64 `json:"baseline" bson:"baseline"`
	}
	var response Response

	// 获取主机总数
	agentHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	total, err := agentHeartCol.CountDocuments(c,
		bson.M{"last_heartbeat_time": bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}})
	if err != nil {
		ylog.Errorf("AgentRisk", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if total == 0 {
		common.CreateResponse(c, common.SuccessCode, response)
		return
	}

	// 获取高可利用漏洞机器总数
	cursor, err := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo).Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"status":      "unprocessed",
				"drop_status": "using",
				"action":      vuln.VulnActionBlock,
			},
		},
		bson.M{
			"$sort": bson.M{
				"agent_id": 1,
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$agent_id",
			},
		},
		bson.M{
			"$count": "count",
		},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if cursor.TryNext(c) {
		cursor.Next(c)
		vulnNum := cursor.Current.Lookup("count").AsInt64()
		response.Vuln = vulnNum * 100 / total
		if response.Vuln > 100 {
			response.Vuln = 100
		}
	}

	// 获取高危基线机器总数
	var groupInfo baseline.GroupInfo
	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	BaselineDefaultList := make([]int, 0)
	err = groupCol.FindOne(context.Background(), bson.M{"group_id": 1}).Decode(&groupInfo)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	for _, baselineInfo := range groupInfo.BaselineList {
		BaselineDefaultList = append(BaselineDefaultList, baselineInfo.BaselineId)
	}
	cursor, err = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl).Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"status":      "failed",
				"if_white":    false,
				"baseline_id": bson.M{"$in": BaselineDefaultList},
			},
		}, bson.M{
			"$sort": bson.M{
				"agent_id": 1,
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$agent_id",
			},
		},
		bson.M{
			"$count": "count",
		},
	})
	if err != nil {
		ylog.Errorf("AgentRisk", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if cursor.TryNext(c) {
		cursor.Next(c)
		baselineNum := cursor.Current.Lookup("count").AsInt64()
		response.Baseline = baselineNum * 100 / total
	}

	// 获取告警机器总数
	cursor, err = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.HubAlarmCollectionV1).Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{
				"__alarm_status": 0,
				"__checked":      true,
				"__hit_wl":       false,
			},
		},
		bson.M{
			"$sort": bson.M{
				"agent_id": 1,
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$agent_id",
			},
		},
		bson.M{
			"$count": "count",
		},
	})
	if err != nil {
		ylog.Errorf("asset-center", err.Error())
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if cursor.TryNext(c) {
		cursor.Next(c)
		alertNum := cursor.Current.Lookup("count").AsInt64()
		response.Alarm = alertNum * 100 / total
	}

	common.CreateResponse(c, common.SuccessCode, response)
}
