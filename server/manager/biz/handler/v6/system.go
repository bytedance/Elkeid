package v6

import (
	"context"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/system_alert"

	"github.com/bytedance/Elkeid/server/manager/internal/monitor"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	alertTemplate "github.com/prometheus/alertmanager/template"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func InsertAlert(c *gin.Context) {
	var newAlert alertTemplate.Data

	err := c.BindJSON(&newAlert)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	for _, alert := range newAlert.Alerts {
		hostIP, ok := alert.Labels["instance"]
		location := system_alert.AlertLocation{}
		if ok {
			location.HostIP = hostIP
			for _, info := range monitor.GetAllHosts() {
				if info.IP == strings.Split(hostIP, ":")[0] {
					location.Hostname = info.ID
					location.Type = "host"
					location.Service = strings.Join(info.Services, ",")
					break
				}
			}
		}
		nowAlert := system_alert.Alert{
			ID:       alert.Fingerprint,
			Name:     alert.Labels["alertname"],
			Content:  alert.Annotations["summary"],
			Severity: alert.Labels["severity"],
			Location: location,
			Status:   alert.Status,
			Suggest:  alert.Annotations["suggestion"],
			Time:     time.Now().Unix(),
		}
		if alert.Status == "firing" {
			nowAlert.FiringTime = time.Now().Unix()
		}
		col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV2)
		AlertResult := col.FindOne(context.Background(), bson.M{"id": alert.Fingerprint})
		if AlertResult.Err() == mongo.ErrNoDocuments {
			if alert.Status == "firing" {
				_, err := col.InsertOne(context.Background(), nowAlert)
				if err != nil {
					ylog.Errorf("InsertAlert", "InsertOne", err.Error())
					continue
				}
			}
		} else {
			dbAlert := system_alert.Alert{}
			err = AlertResult.Decode(&dbAlert)
			if err != nil {
				ylog.Errorf("InsertAlert", "Decode", err.Error())
				continue
			}
			if dbAlert.Status == "ignored" {
				continue
			}
			if alert.Status == "resolved" {
				nowAlert.ResolveTime = time.Now().Unix()
				_, err = col.UpdateOne(context.Background(), bson.M{"id": alert.Fingerprint}, bson.M{"$set": bson.M{"status": alert.Status, "resolve_time": time.Now().Unix(), "time": time.Now().Unix()}})
				if err != nil {
					ylog.Errorf("InsertAlert", "UpdateOne", err.Error())
					continue
				}
			} else {
				_, err = col.UpdateOne(context.Background(), bson.M{"id": alert.Fingerprint}, bson.M{"$set": bson.M{"status": alert.Status, "firing_time": time.Now().Unix(), "time": time.Now().Unix()}})
				if err != nil {
					ylog.Errorf("InsertAlert", "UpdateOne", err.Error())
					continue
				}
			}
		}

	}

	common.CreateResponse(c, common.SuccessCode, "ok")
}
func AlertStatistics(c *gin.Context) {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV2)

	var pendingCount int64 = 0
	var oneDayCount int64 = 0
	var oneWeekCount int64 = 0
	end := time.Now().Unix()
	start := end - 3600*24
	pendingCount, err := col.CountDocuments(context.Background(), bson.M{"time": bson.M{"$gte": start, "$lte": end}, "status": "firing"})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	oneDayCount, err = col.CountDocuments(context.Background(), bson.M{"time": bson.M{"$gte": start, "$lte": end}, "status": bson.M{"$ne": "resolved"}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	start = end - 3600*24*7
	oneWeekCount, err = col.CountDocuments(context.Background(), bson.M{"time": bson.M{"$gte": start, "$lte": end}, "status": bson.M{"$ne": "resolved"}})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var alertStatistics = map[string]int64{
		"pending_last1d": pendingCount,
		"total_last1d":   oneDayCount,
		"total_last1w":   oneWeekCount,
	}
	common.CreateResponse(c, common.SuccessCode, alertStatistics)
}

func AlertList(c *gin.Context) {
	window := c.Query("window")
	alertFilter := c.Query("filter")

	var pageRequest common.PageRequest
	err := c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetClusterConfigList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// mongo查询并迭代处理

	if window == "" {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "param invalid")
		return
	}
	filter := bson.M{"status": nil, "time": nil}
	if alertFilter == "" {
		filter["status"] = bson.M{"$ne": "resolved"}
	} else if alertFilter == "ignored" {
		filter["status"] = "ignored"
	} else {
		filter["status"] = "firing"
	}

	if window == "last-24h" {
		end := time.Now().Unix()
		start := end - 3600*24
		filter["time"] = bson.M{"$gte": start, "$lte": end}
	} else {
		end := time.Now().Unix()
		start := end - 3600
		filter["time"] = bson.M{"$gte": start, "$lte": end}
	}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV2)
	SysAlertList := make([]system_alert.Alert, 0)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: filter, Sorter: nil}
	pageResponse, err := common.DBSearchPaginate(
		col,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var SysAlert system_alert.Alert
			err := cursor.Decode(&SysAlert)
			if err != nil {
				ylog.Errorf("GetClusterConfigList", err.Error())
				return err
			}
			SysAlertList = append(SysAlertList, SysAlert)
			return nil
		},
	)
	//cur, err := col.Find(context.Background(), filter)
	//if err != nil {
	//	common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	//	return
	//}
	//for cur.Next(context.Background()) {
	//	var alert Alert
	//	err := cur.Decode(&alert)
	//	if err != nil {
	//		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	//		return
	//	}
	//	alerts = append(alerts, alert)
	//}
	CreatePageResponse(c, common.SuccessCode, SysAlertList, *pageResponse)
}

type alertList struct {
	Alerts []string `json:"alerts"`
}
type idList struct {
	Alerts []string `json:"id_list" `
}

func IgnoreAlerts(c *gin.Context) {
	var ignoreAlerts alertList
	err := c.BindJSON(&ignoreAlerts)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if len(ignoreAlerts.Alerts) == 0 {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "alert list is empty")
		return
	}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV2)
	for _, alert := range ignoreAlerts.Alerts {
		_, err := col.UpdateOne(context.Background(), bson.M{"id": alert}, bson.M{"$set": bson.M{"status": "ignored"}})
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}
	common.CreateResponse(c, common.SuccessCode, "ok")
}

func ExportAlerts(c *gin.Context) {
	var Alerts idList
	err := c.BindJSON(&Alerts)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	window := c.Query("window")

	if len(Alerts.Alerts) == 0 && window == "" {

		common.CreateResponse(c, common.ParamInvalidErrorCode, "Please input idList or window")
		return
	}
	filter := bson.M{}
	if len(Alerts.Alerts) > 0 {
		filter = bson.M{"id": bson.M{"$in": Alerts.Alerts}}
	} else {
		filter = bson.M{}
		if window == "last-24h" {
			end := time.Now().Unix()
			start := end - 3600*24
			filter = bson.M{"time": bson.M{"$gte": start, "$lte": end}}
		} else {
			end := time.Now().Unix()
			start := end - 3600
			filter = bson.M{"time": bson.M{"$gte": start, "$lte": end}}
		}
	}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV2)
	filename := "Exported-SystemAlert"
	common.ExportFromMongoDB(c, col, filter, system_alert.SystemAlertHeaders, filename)

}
func ResetAlerts(c *gin.Context) {
	var resetAlerts alertList
	err := c.BindJSON(&resetAlerts)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	if len(resetAlerts.Alerts) == 0 {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "alert list is empty")
		return
	}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV2)
	for _, alert := range resetAlerts.Alerts {
		_, err = col.UpdateOne(context.Background(), bson.M{"id": alert}, bson.M{"$set": bson.M{"status": "firing"}})
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
	}
	common.CreateResponse(c, common.SuccessCode, "ok")
}
func DescribeAlerts(ctx *gin.Context) {
	pq := common.PageRequest{}
	err := ctx.BindQuery(&pq)
	if err != nil {
		common.CreateResponse(ctx, common.ParamInvalidErrorCode, err.Error())
		return
	}

	c := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.SystemAlertCollectionV1)
	pageRequest := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   bson.M{},
		Sorter:   nil,
	}

	data := make([]map[string]interface{}, 0, pq.PageSize)
	pageResponse, err := common.DBSearchPaginate(c, pageRequest, func(c *mongo.Cursor) error {
		item := map[string]interface{}{}
		err := c.Decode(&item)
		if err != nil {
			ylog.Errorf("DescribeAlerts", err.Error())
			return err
		}
		data = append(data, item)
		return nil
	})

	if err != nil {
		common.CreateResponse(ctx, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(ctx, common.SuccessCode, data, *pageResponse)
	}
}
