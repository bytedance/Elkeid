package vuln

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"strconv"
	"time"
)

// 每日清空历史漏洞信息
const FlushVulnInfoLock = "FlushVulnInfoLock"

func FlushVulnInfo() {
	c := context.Background()
	myFunc := func() {
		dailyTicker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, 6, 0, 0, 0, time.Now().Location())))
		dailyInit := true
		for {
			select {
			case <-dailyTicker.C:
				if dailyInit {
					dailyTicker.Reset(time.Hour * 24)
					dailyInit = false
				}
				todayTimeData := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Local)
				todayTimeStamp := todayTimeData.Unix()
				todayTimeStampStr := strconv.FormatInt(todayTimeStamp, 10)
				softCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintSoftwareCollection)
				agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
				agentVulnSoftCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnSoftInfo)

				agentIdList, err := softCol.Distinct(c, "agent_id", bson.M{"time": bson.M{"$gt": todayTimeStampStr}})
				if len(agentIdList) == 0 || err != nil {
					break
				}

				_, err = agentVulnCol.DeleteMany(c, bson.M{"update_time": bson.M{"$lt": todayTimeStamp}, "agent_id": bson.M{"$in": agentIdList}})
				if err != nil {
					ylog.Errorf("Delete error", err.Error())
				}
				_, err = agentVulnSoftCol.DeleteMany(c, bson.M{"update_time": bson.M{"$lt": todayTimeStamp}, "agent_id": bson.M{"$in": agentIdList}})
				if err != nil {
					ylog.Errorf("Delete error", err.Error())
				}

			}
		}
	}

	lockSuccess, err := infra.Grds.SetNX(context.Background(), FlushVulnInfoLock, 1, time.Minute*time.Duration(5)).Result()
	if err != nil || !lockSuccess {
		return
	} else {
		myFunc()
		_, err := infra.Grds.Del(context.Background(), FlushVulnInfoLock).Result()
		if err != nil {
			return
		}
	}
}

// 定时计算漏洞列表mongo
const CalcuVulnHeartLock = "CalcuVulnHeartLock"

func CalcuVulnList(calcuType string) {
	c := context.Background()
	Calcu := func() {
		// 获取旧的漏洞信息
		oldVulnHeartMap := make(map[int64]VulnHeart)
		vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)
		cur, err := vulnHeartCol.Find(c, bson.M{})
		if err == nil {
			for cur.Next(c) {
				var vulnHeartBeat VulnHeart
				err := cur.Decode(&vulnHeartBeat)
				if err != nil {
					ylog.Infof("Decode error", err.Error())
				}
				oldVulnHeartMap[vulnHeartBeat.VulnId] = vulnHeartBeat
			}
		}

		// 计算agent_vuln 漏洞统计数据
		agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
		var aggregateSearchList bson.A
		aggregateSearchList = append(aggregateSearchList, bson.M{"$match": bson.M{"drop_status": VulnDropStatusUse}})
		aggregateSearchList = append(aggregateSearchList, bson.M{"$group": bson.M{
			"_id":         bson.M{"vuln_id": "$vuln_id", "status": "$status"},
			"infect_num":  bson.M{"$sum": 1},
			"update_time": bson.M{"$max": "$update_time"},
		}})

		type tmpStruct struct {
			Key struct {
				VulnId int64  `json:"vuln_id" bson:"vuln_id"`
				Status string `json:"status" bson:"status"`
			} `json:"key" bson:"_id"`
			InfectNum  int   `json:"infect_num" bson:"infect_num"`
			UpdateTime int64 `json:"update_time" bson:"update_time"`
		}

		// 生成心跳漏洞表
		var vulnIdList []int64
		vulnHeartMap := make(map[int64]VulnHeart, 0)
		cursor, _ := agentVulnCol.Aggregate(c, aggregateSearchList)
		for cursor.Next(c) {
			var tmpS tmpStruct
			err := cursor.Decode(&tmpS)
			if err != nil {
				continue
			}

			vulnId := tmpS.Key.VulnId
			var vulnHeart VulnHeart
			if _, ok := vulnHeartMap[vulnId]; !ok {
				vulnIdList = append(vulnIdList, vulnId)
				vulnHeart.VulnId = vulnId
			} else {
				vulnHeart = vulnHeartMap[vulnId]
			}

			// 计算漏洞影响资产具体数量
			vulnHeart.InfectNum += tmpS.InfectNum
			switch tmpS.Key.Status {
			case VulnStatusUnProcessed:
				vulnHeart.InfectStatus.UnProcessed += tmpS.InfectNum
			case VulnStatusProcessed:
				vulnHeart.InfectStatus.Processed += tmpS.InfectNum
			case VulnStatusIgnored:
				vulnHeart.InfectStatus.Ignore += tmpS.InfectNum
			}
			if tmpS.UpdateTime > vulnHeart.UpdateTime {
				vulnHeart.UpdateTime = tmpS.UpdateTime
			}
			vulnHeartMap[vulnId] = vulnHeart
		}

		if len(vulnIdList) == 0 {
			return
		}

		// 生成漏洞信息
		levelMap := map[string]string{
			"1": "low",
			"2": "low",
			"3": "mid",
			"4": "high",
			"5": "danger",
		}
		vulnHeartWrite := make([]mongo.WriteModel, 0, len(vulnIdList))
		vulnInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
		cursor, _ = vulnInfoCol.Find(c, bson.M{"id": bson.M{"$in": vulnIdList}})

		for cursor.Next(c) {
			var vulnInfo VulnInfo
			err := cursor.Decode(&vulnInfo)
			if err != nil {
				continue
			}
			vulnId := vulnInfo.VulnId
			vulnHeart := vulnHeartMap[vulnId]
			vulnHeart.CveId = vulnInfo.CveId
			vulnHeart.Level = levelMap[vulnInfo.Level]
			vulnHeart.VulnName = vulnInfo.VulnName
			vulnHeart.VulnNameEn = vulnInfo.VulnNameEn
			vulnHeart.Action = vulnInfo.Action
			if _, ok := vulnHeartMap[vulnId]; ok {
				vulnHeart.OperateReason = oldVulnHeartMap[vulnId].OperateReason
				vulnHeart.ControlTime = oldVulnHeartMap[vulnId].ControlTime
				vulnHeart.Status = oldVulnHeartMap[vulnId].Status
			}
			if vulnInfo.Cwe != "" {
				vulnHeart.Tag = append(vulnHeart.Tag, vulnInfo.Cwe)
			}
			if vulnInfo.IfExp == 1 {
				vulnHeart.Tag = append(vulnHeart.Tag, HasEXP)
			}

			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"vuln_id": vulnHeart.VulnId}).
				SetUpdate(bson.M{"$set": vulnHeart}).
				SetUpsert(true)
			vulnHeartWrite = append(vulnHeartWrite, model)
		}

		// 更新漏洞表
		writeOption := &options.BulkWriteOptions{}
		writeOption.SetOrdered(false)
		_, err = vulnHeartCol.BulkWrite(context.Background(), vulnHeartWrite, writeOption)
		if err != nil {
			ylog.Errorf("BulkWrite error", err.Error())
		}

		// 删除多余的漏洞
		cursor, _ = vulnHeartCol.Find(c, bson.M{}, options.Find().SetProjection(bson.M{"vuln_id": 1}))
		var delVulnIdList []int64
		for cursor.Next(c) {
			tmpStruct2 := struct {
				VulnId int64 `bson:"vuln_id"`
			}{}
			err := cursor.Decode(&tmpStruct2)
			if err != nil {
				continue
			}

			if _, ok := vulnHeartMap[tmpStruct2.VulnId]; !ok {
				delVulnIdList = append(delVulnIdList, tmpStruct2.VulnId)
			}
		}
		if len(delVulnIdList) != 0 {
			_, err := vulnHeartCol.DeleteMany(c, bson.M{"vuln_id": bson.M{"$in": delVulnIdList}})
			if err != nil {
				ylog.Errorf("Delete error", err.Error())
			}
		}

	}

	if calcuType == "crontab" {
		timer := time.NewTicker(time.Minute * time.Duration(5))
		for {
			select {
			case <-timer.C:
				lockSuccess, err := infra.Grds.SetNX(context.Background(), CalcuVulnHeartLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					Calcu()
					_, err := infra.Grds.Del(context.Background(), CalcuVulnHeartLock).Result()
					if err != nil {
						continue
					}
				}
			}
		}
	} else if calcuType == "once" {
		lockSuccess, err := infra.Grds.SetNX(context.Background(), CalcuVulnHeartLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			Calcu()
			_, err := infra.Grds.Del(context.Background(), CalcuVulnHeartLock).Result()
			if err != nil {
				return
			}
		}
	}
}

// 定时写入漏洞进程关联表
const WriteVulnProccessLock = "WriteVulnProccessLock"

func WriteVulnProcessList(calcuType string) {
	c := context.Background()

	writeProcessList := func() {
		vulnProcessInfoList := make([]interface{}, 0)
		agentSoftVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnSoftInfo)
		agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
		vulnInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
		vulnProcessCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnProcess)

		// 清空vulnProcess历史数据
		_, err := vulnProcessCol.DeleteMany(c, bson.M{})
		if err != nil {
			ylog.Errorf("Delete error", err.Error())
		}

		cur, _ := agentVulnCol.Find(c, bson.M{"action": VulnActionBlock, "drop_status": VulnDropStatusUse})
		for cur.Next(c) {
			tmpS := struct {
				AgentId       string `json:"agent_id" bson:"agent_id"`
				VulnId        int    `json:"vuln_id" bson:"vuln_id"`
				CreateTime    int64  `json:"create_time" bson:"create_time"`
				UpdateTime    int64  `json:"update_time" bson:"update_time"`
				ControlTime   int64  `json:"control_time" bson:"control_time"`
				OperateReason string `json:"operate_reason" bson:"operate_reason"`
			}{}
			err := cur.Decode(&tmpS)
			if err != nil {
				continue
			}

			var agentVulnSoftInfo AgentVulnSoftInfo
			var vulnProcessInfo VulnProcessInfo
			err = agentSoftVulnCol.FindOne(c, bson.M{"agent_id": tmpS.AgentId, "vuln_id": tmpS.VulnId}).Decode(&agentVulnSoftInfo)
			if err != nil {
				continue
			}
			if len(agentVulnSoftInfo.PidList) != 0 {
				var vulnInfo VulnInfo
				err := vulnInfoCol.FindOne(c, bson.M{"id": tmpS.VulnId}).Decode(&vulnInfo)
				if err != nil {
					ylog.Infof("Find error", err.Error())
				}
				for _, pidStruct := range agentVulnSoftInfo.PidList {
					vulnProcessInfo = VulnProcessInfo{
						Cve:           vulnInfo.CveId,
						Severity:      vulnInfo.Level,
						TitleCn:       vulnInfo.VulnName,
						AgentId:       tmpS.AgentId,
						Pid:           pidStruct.Pid,
						Cmd:           pidStruct.Cmd,
						VulnId:        vulnInfo.VulnId,
						CreateTime:    tmpS.CreateTime,
						UpdateTime:    tmpS.UpdateTime,
						ControlTime:   tmpS.ControlTime,
						OperateReason: tmpS.OperateReason,
					}
					vulnProcessInfo.Tag = make([]string, 0)
					vulnProcessInfo.Tag = append(vulnProcessInfo.Tag, vulnInfo.Cwe)
					if vulnInfo.IfExp == 1 {
						vulnProcessInfo.Tag = append(vulnProcessInfo.Tag, HasEXP)
					}
					vulnProcessInfoList = append(vulnProcessInfoList, vulnProcessInfo)
				}
			}
		}
		if len(vulnProcessInfoList) != 0 {
			_, err := vulnProcessCol.InsertMany(c, vulnProcessInfoList)
			if err != nil {
				ylog.Errorf("Insert error", err.Error())
			}
		}
	}

	if calcuType == "crontab" {

		dailyTicker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, 6, 0, 0, 0, time.Now().Location())))
		dailyInit := true
		for {
			select {
			case <-dailyTicker.C:
				if dailyInit {
					dailyTicker.Reset(time.Hour * 24)
					dailyInit = false
				}
				lockSuccess, err := infra.Grds.SetNX(context.Background(), WriteVulnProccessLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					writeProcessList()
					_, err := infra.Grds.Del(context.Background(), WriteVulnProccessLock).Result()
					if err != nil {
						continue
					}
				}
			}
		}

	} else if calcuType == "once" {
		lockSuccess, err := infra.Grds.SetNX(context.Background(), WriteVulnProccessLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			writeProcessList()
			_, err := infra.Grds.Del(context.Background(), WriteVulnProccessLock).Result()
			if err != nil {
				return
			}
		}
	}
}

// 判断漏洞是否超时
func JudgeVulnTaskTimeout() {
	ctx := context.Background()
	taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnTaskStatus)

	findOption := options.Find()
	findOption.SetSort(bson.M{"last_check_time": 1})
	cur, _ := taskStatusCol.Find(ctx, bson.M{"status": "running"}, findOption)

	timeNow := time.Now().Unix()
	var taskStatus VulnTaskStatus
	var agentList []string
	for cur.Next(ctx) {
		_ = cur.Decode(&taskStatus)
		if timeNow-taskStatus.LastCheckTime > VulnTaskTimeout {
			agentList = append(agentList, taskStatus.AgentId)
		} else {
			break
		}
	}

	if len(agentList) == 0 {
		return
	}
	taskStatusWrite := make([]mongo.WriteModel, 0, len(agentList))

	// 更新超时的任务
	taskeUpdateJson := bson.M{"status": "error", "msg": "timeout"}
	for _, agent_id := range agentList {
		// 更新任务状态
		model := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"agent_id": agent_id}).
			SetUpdate(bson.M{"$set": taskeUpdateJson})
		taskStatusWrite = append(taskStatusWrite, model)

	}

	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	_, err := taskStatusCol.BulkWrite(ctx, taskStatusWrite, writeOption)
	if err != nil {
		ylog.Errorf("BulkWrite error", err.Error())
	}
	return
}

// 计算漏洞统计信息
func vulnStatustic() {
	// 漏洞数计算入库
	c := context.Background()
	dailyTicker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, 1, 0, 0, 0, time.Now().Location())))
	dailyInit := true

	for {
		select {
		case <-dailyTicker.C:
			if dailyInit {
				dailyTicker.Reset(time.Hour * 24)
				dailyInit = false
			}
			// 计算当日漏洞总数
			vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)
			vulnNum, _ := vulnHeartCol.CountDocuments(c, bson.M{"infect_status.unprocessed": bson.M{"$ne": 0}, "action": VulnActionBlock})

			vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)
			var vulnConf7Day VulnConf7Day
			vulnDaily := VulnDaily{
				Date:    time.Now().Unix(),
				VulnNum: vulnNum,
			}
			err := vulnConfCol.FindOne(c, bson.M{"type": VulnConf7DayList}).Decode(&vulnConf7Day)
			if err != nil {
				ylog.Infof("Find error", err.Error())
			}
			newList := make([]VulnDaily, 0)
			newList = append(newList, vulnDaily)
			for i, vulnInfo := range vulnConf7Day.Day7List {
				newList = append(newList, vulnInfo)
				if i >= 9 {
					break
				}
			}
			vulnConf7Day.Day7List = newList
			_, err = vulnConfCol.UpdateOne(c, bson.M{"type": VulnConf7DayList}, bson.M{"$set": vulnConf7Day})
			if err != nil {
				ylog.Errorf("Update error", err.Error())
			}
		}
	}
}
