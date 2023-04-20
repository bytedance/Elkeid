package baseline

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

// 定时计算基线统计信息
type CalcuBaselineStatisticRes struct {
	PassRate      int    `json:"pass_rate"`
	PassNum       int64  `json:"pass_num"`
	RiskNum       int64  `json:"risk_num"`
	HostNum       int64  `json:"host_num"`
	ChecklistNum  int64  `json:"checklist_num"`
	Status        string `json:"status"`
	RiskHostNum   int64  `json:"risk_host_num"`
	PassHostNum   int64  `json:"pass_host_num"`
	LastCheckTime int64  `json:"last_check_time"`
}

var BaselineStatisticMap = make(map[int]CalcuBaselineStatisticRes, 0)

func calcuBaselineStatistic() {
	c := context.Background()
	agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	baselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
	groupCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)

	// 获取基线信息
	baselineInfoList := make([]BaselineInfo, 0)
	cur, err := baselineCol.Find(c, bson.M{})
	if err != nil {
		return
	}
	for cur.Next(c) {
		var baselineInfo BaselineInfo
		err = cur.Decode(&baselineInfo)
		baselineInfoList = append(baselineInfoList, baselineInfo)
	}

	// 获取策略组信息
	groupInfoList := make([]GroupInfo, 0)
	cur, err = groupCol.Find(c, bson.M{})
	if err != nil {
		return
	}
	for cur.Next(c) {
		var groupInfo GroupInfo
		err = cur.Decode(&groupInfo)
		groupInfoList = append(groupInfoList, groupInfo)
	}

	// 主机数统计
	for _, baselineInfo := range baselineInfoList {
		var statisRes CalcuBaselineStatisticRes
		baselineId := baselineInfo.BaselineId
		cur, _ := agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": baselineId}},
			bson.M{"$group": bson.M{"_id": "$agent_id"}},
			bson.M{"$count": "count"},
		})
		if cur.TryNext(c) {
			cur.Next(c)
			statisRes.HostNum = cur.Current.Lookup("count").AsInt64()
		}
		cur, _ = agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": baselineId, "if_white": false, "status": StatusFailed}},
			bson.M{"$group": bson.M{"_id": "$agent_id"}},
			bson.M{"$count": "count"},
		})
		if cur.TryNext(c) {
			cur.Next(c)
			statisRes.RiskHostNum = cur.Current.Lookup("count").AsInt64()
		}
		statisRes.PassHostNum = statisRes.HostNum - statisRes.RiskHostNum

		// 检查项以及通过率
		cur, _ = agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": baselineId, "if_white": false, "status": StatusFailed}},
			bson.M{"$group": bson.M{"_id": "$check_id"}},
			bson.M{"$count": "count"},
		})
		if cur.TryNext(c) {
			cur.Next(c)
			statisRes.RiskNum = cur.Current.Lookup("count").AsInt64()
		}

		statisRes.ChecklistNum = int64(len(baselineInfo.CheckIdList))
		statisRes.PassNum = statisRes.ChecklistNum - statisRes.RiskNum
		if statisRes.ChecklistNum != 0 {
			statisRes.PassRate = int(statisRes.PassNum * 100 / statisRes.ChecklistNum)
		}
		BaselineStatisticMap[baselineId] = statisRes
	}

	// 策略组统计
	for _, groupInfo := range groupInfoList {
		// 获取group的baseline列表
		groupId := groupInfo.GroupId
		baselineList := make([]int, 0)

		for _, baselineInfo := range groupInfo.BaselineList {
			baselineList = append(baselineList, baselineInfo.BaselineId)
		}

		// 计算检查主机数
		var statisRes CalcuBaselineStatisticRes
		cur, err := agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": bson.M{"$in": baselineList}}},
			bson.M{"$group": bson.M{"_id": "$agent_id"}},
			bson.M{"$count": "count"},
		})
		if err != nil {
			continue
		}
		if cur.TryNext(c) {
			cur.Next(c)
			statisRes.HostNum = cur.Current.Lookup("count").AsInt64()
		}

		// 计算其他统计数据
		for _, baselineId := range baselineList {
			var baselineSta CalcuBaselineStatisticRes
			if _, ok := BaselineStatisticMap[baselineId]; ok {
				baselineSta = BaselineStatisticMap[baselineId]
				statisRes.RiskNum += baselineSta.RiskNum
				statisRes.ChecklistNum += baselineSta.ChecklistNum
				statisRes.PassHostNum += baselineSta.PassHostNum
				statisRes.RiskHostNum += baselineSta.RiskHostNum
			}
		}
		statisRes.PassNum = statisRes.ChecklistNum - statisRes.RiskNum
		if statisRes.ChecklistNum != 0 {
			statisRes.PassRate = int(statisRes.PassNum * 100 / statisRes.ChecklistNum)
		}
		BaselineStatisticMap[groupId] = statisRes
	}
}

// 判断任务超时
const BaselineJudgeTaskLock = "BaselineJudgeTaskLock"
const BaselineCalcuBaselineStatistic = "BaselineCalcuBaselineStatistic"

func judgeTaskTimeout(calcuType string) {
	ifJudgeTaskTimeout := true
	judgeFunc := func() {
		ctx := context.Background()
		taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
		agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

		findOption := options.Find()
		findOption.SetSort(bson.M{"last_check_time": 1})
		cur, _ := taskStatusCol.Find(ctx, bson.M{"status": "running"}, findOption)

		// 更新基线任务
		timeNow := time.Now().Unix()
		var taskStatus BaselineTaskStatus
		var UpdateTaskInfo []BaselineTaskStatus
		ifTaskFinish := true
		for cur.Next(ctx) {
			ifTaskFinish = false
			_ = cur.Decode(&taskStatus)
			if timeNow-taskStatus.LastCheckTime > BaselineTaskTimeout {
				UpdateTaskInfo = append(UpdateTaskInfo, taskStatus)
			} else {
				break
			}
		}

		if len(UpdateTaskInfo) != 0 {
			taskStatusWrite := make([]mongo.WriteModel, 0, len(UpdateTaskInfo))

			// 更新超时的任务
			taskeUpdateJson := bson.M{"status": "error", "msg": BaselinCheckTimeout}
			for _, taskInfo := range UpdateTaskInfo {
				// 更新任务状态
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"agent_id": taskInfo.AgentId, "baseline_id": taskInfo.BaselineId}).
					SetUpdate(bson.M{"$set": taskeUpdateJson})
				taskStatusWrite = append(taskStatusWrite, model)
			}
			writeOption := &options.BulkWriteOptions{}
			writeOption.SetOrdered(false)
			_, err := taskStatusCol.BulkWrite(ctx, taskStatusWrite, writeOption)
			if err != nil {
				ylog.Infof("mongo bulkwrite err", err.Error())
			}
		}

		// 更新检查项任务
		findOption = options.Find()
		findOption.SetSort(bson.M{"update_time": 1})
		cur, _ = agentBaseCol.Find(ctx, bson.M{"task_status": "running"}, findOption)

		var agentBaseline AgentBaselineInfo
		var UpdateCheckTaskInfo []AgentBaselineInfo
		ifAgentBaseFinish := true
		for cur.Next(ctx) {
			ifAgentBaseFinish = false
			_ = cur.Decode(&agentBaseline)
			if timeNow-agentBaseline.UpdateTime > BaselineTaskTimeout {
				UpdateCheckTaskInfo = append(UpdateCheckTaskInfo, agentBaseline)
			} else {
				break
			}
		}

		if len(UpdateCheckTaskInfo) != 0 {
			taskStatusWrite := make([]mongo.WriteModel, 0, len(UpdateCheckTaskInfo))

			// 更新超时的任务
			taskeUpdateJson := bson.M{"status": "error", "err_reason": BaselinCheckTimeout, "task_status": "finished"}
			for _, taskInfo := range UpdateCheckTaskInfo {
				// 更新任务状态
				model := mongo.NewUpdateOneModel().
					SetFilter(bson.M{"agent_id": taskInfo.AgentId, "baseline_id": taskInfo.BaselineId, "check_id": taskInfo.CheckId}).
					SetUpdate(bson.M{"$set": taskeUpdateJson})
				taskStatusWrite = append(taskStatusWrite, model)
			}
			writeOption := &options.BulkWriteOptions{}
			writeOption.SetOrdered(false)
			_, err := agentBaseCol.BulkWrite(ctx, taskStatusWrite, writeOption)
			if err != nil {
				ylog.Infof("mongo bulkwrite err", err.Error())
			}
		}
		if ifTaskFinish && ifAgentBaseFinish {
			ifJudgeTaskTimeout = false
		}

		// 计算检查通过率
		for _, baseline_id := range BaselineAllIdList {
			go SetBaselineCheckTask(baseline_id, "once")
		}
		return
	}

	if calcuType == "crontab" {
		timer := time.NewTicker(time.Second * time.Duration(10))
		for {
			select {
			case <-timer.C:
				if !ifJudgeTaskTimeout {
					break
				}
				lockSuccess, err := infra.Grds.SetNX(context.Background(), BaselineJudgeTaskLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					judgeFunc()
					_, err := infra.Grds.Del(context.Background(), BaselineJudgeTaskLock).Result()
					if err != nil {
						continue
					}
				}
				lockSuccess, err = infra.Grds.SetNX(context.Background(), BaselineCalcuBaselineStatistic, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					calcuBaselineStatistic()
					_, err := infra.Grds.Del(context.Background(), BaselineCalcuBaselineStatistic).Result()
					if err != nil {
						continue
					}
				}
			}
		}
	}
	if calcuType == "crontab_back" {
		timer := time.NewTicker(time.Hour * time.Duration(2))
		for {
			select {
			case <-timer.C:
				lockSuccess, err := infra.Grds.SetNX(context.Background(), BaselineJudgeTaskLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					judgeFunc()
					_, err := infra.Grds.Del(context.Background(), BaselineJudgeTaskLock).Result()
					if err != nil {
						continue
					}
				}
				lockSuccess, err = infra.Grds.SetNX(context.Background(), BaselineCalcuBaselineStatistic, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					calcuBaselineStatistic()
					_, err := infra.Grds.Del(context.Background(), BaselineCalcuBaselineStatistic).Result()
					if err != nil {
						continue
					}
				}
				lockSuccess, err = infra.Grds.SetNX(context.Background(), setBaselineCheckTaskLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					SetBaselineCheckTask(0, "once")
					_, err := infra.Grds.Del(context.Background(), setBaselineCheckTaskLock).Result()
					if err != nil {
						continue
					}
				}
			}
		}
	}
	if calcuType == "once" {
		lockSuccess, err := infra.Grds.SetNX(context.Background(), BaselineJudgeTaskLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			judgeFunc()
			_, err := infra.Grds.Del(context.Background(), BaselineJudgeTaskLock).Result()
			if err != nil {
				return
			}
		}
		lockSuccess, err = infra.Grds.SetNX(context.Background(), BaselineCalcuBaselineStatistic, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			calcuBaselineStatistic()
			_, err := infra.Grds.Del(context.Background(), BaselineCalcuBaselineStatistic).Result()
			if err != nil {
				return
			}
		}
		lockSuccess, err = infra.Grds.SetNX(context.Background(), setBaselineCheckTaskLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			SetBaselineCheckTask(0, "once")
			_, err := infra.Grds.Del(context.Background(), setBaselineCheckTaskLock).Result()
			if err != nil {
				return
			}
		}
	}
}

// 计算检查项任务状态表
const setBaselineCheckTaskLock = "setBaselineCheckTaskLock"

func SetBaselineCheckTask(baselineId int, calcuType string) {
	myFunc := func() {
		c := context.Background()
		checkInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineCheckInfoColl)
		baselineInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
		agentBaseCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)

		// 计算机器总数
		hostNum := 0
		cur, _ := agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": baselineId, "check_id": 1}},
			bson.M{"$count": "count"},
		})
		if cur.TryNext(c) {
			cur.Next(c)
			hostNum = int(cur.Current.Lookup("count").AsInt64())
		}

		// 计算通过率
		checkPassRateMap := make(map[int]int, 0)
		taskStatusWrite := make([]mongo.WriteModel, 0)
		cur, _ = agentBaseCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{"baseline_id": baselineId, "if_white": false, "status": StatusFailed}},
			bson.M{"$group": bson.M{"_id": "$check_id", "total": bson.M{"$sum": 1}}},
		})
		for cur.Next(c) {
			tmpS := struct {
				CheckId int `bson:"_id"`
				Total   int `bson:"total"`
			}{}
			err := cur.Decode(&tmpS)
			if err != nil {
				ylog.Infof("Decode", err.Error())
			}
			passRate := 100 - (tmpS.Total * 100 / hostNum)
			checkPassRateMap[tmpS.CheckId] = passRate
		}

		// 更新检查项信息
		var baselineInfo BaselineInfo
		err := baselineInfoCol.FindOne(c, bson.M{"baseline_id": baselineId}).Decode(&baselineInfo)
		if err != nil {
			ylog.Infof("Find error", err.Error())
		}
		for _, checkId := range baselineInfo.CheckIdList {
			passRate := 100
			if v, ok := checkPassRateMap[checkId]; ok {
				passRate = v
			}

			num, _ := agentBaseCol.CountDocuments(c, bson.M{"baseline_id": baselineId, "check_id": checkId, "task_status": "running"})
			status := "finished"
			if num > 0 {
				status = "running"
			}

			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"baseline_id": baselineId, "check_id": checkId}).
				SetUpdate(bson.M{"$set": bson.M{"pass_rate": passRate, "status": status}})
			taskStatusWrite = append(taskStatusWrite, model)
		}

		writeOption := &options.BulkWriteOptions{}
		writeOption.SetOrdered(false)
		_, err = checkInfoCol.BulkWrite(c, taskStatusWrite, writeOption)
		if err != nil {
			ylog.Infof("BulkWrite error", err.Error())
			return
		}
		return
	}

	if calcuType == "crontab" {
		timer := time.NewTicker(time.Hour * time.Duration(2))
		for {
			select {
			case <-timer.C:
				lockSuccess, err := infra.Grds.SetNX(context.Background(), setBaselineCheckTaskLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					for _, baseline_id := range BaselineAllIdList {
						baselineId = baseline_id
						myFunc()
					}
					_, err := infra.Grds.Del(context.Background(), setBaselineCheckTaskLock).Result()
					if err != nil {
						continue
					}
				}
			}
		}
	} else if calcuType == "once" {
		lockSuccess, err := infra.Grds.SetNX(context.Background(), setBaselineCheckTaskLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			myFunc()
			_, err := infra.Grds.Del(context.Background(), setBaselineCheckTaskLock).Result()
			if err != nil {
				return
			}
		}
	}
}
