package rasp

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

// rasp进程定期同步
const RaspSyncLock = "RaspSyncLock"

func RaspSync(calcuType string) {
	c := context.Background()

	levelMap := map[string]string{
		"1": "low",
		"2": "low",
		"3": "mid",
		"4": "high",
		"5": "danger",
	}
	syncFunc := func() {
		// 获取热补丁漏洞列表 raspVulnIdList
		vulnInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
		cur, _ := vulnInfoCol.Find(c, bson.M{"if_rasp": true})
		raspVulnIdList := make([]int64, 0)
		for cur.Next(c) {
			id, ok := cur.Current.Lookup("id").AsInt64OK()
			if ok {
				raspVulnIdList = append(raspVulnIdList, id)
			}
		}

		// 漏洞进程和rasp进程联查
		raspProcessWrites := make([]mongo.WriteModel, 0)
		vulnProcessCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnProcess)
		cursor, _ := vulnProcessCol.Aggregate(c, bson.A{
			bson.M{"$match": bson.M{
				"vuln_id": bson.M{"$in": raspVulnIdList},
			}},
			bson.M{
				"$lookup": bson.M{
					"from": infra.FingerprintRaspCollection,
					"let":  bson.M{"agent_id": "$agent_id", "pid": "$pid"},
					"pipeline": bson.A{
						bson.M{
							"$match": bson.M{
								"$expr": bson.M{
									"$and": bson.A{
										bson.M{"$eq": bson.A{"$agent_id", "$$agent_id"}},
										bson.M{"$eq": bson.A{"$pid", "$$pid"}},
									}}},
						},
					},
					"as": "rasp_heartbeat",
				},
			},
			bson.M{"$match": bson.M{"rasp_heartbeat.0": bson.M{"$exists": true}}},
		})
		type tmpSearchStruct struct {
			AgentId       string   `json:"agent_id" bson:"agent_id"`
			VulnId        int64    `json:"vuln_id" bson:"vuln_id"`
			TitleCn       string   `json:"title_cn" bson:"title_cn"`
			Pid           string   `json:"pid" bson:"pid"`
			Cmd           string   `json:"cmd" bson:"cmd"`
			Cve           string   `json:"cve" bson:"cve"`
			Tag           []string `json:"tag" bson:"tag"`
			Status        string   `json:"status" bson:"status"`
			Severity      string   `json:"severity" bson:"severity"`
			CreateTime    int64    `json:"create_time" bson:"create_time"`
			UpdateTime    int64    `json:"update_time" bson:"update_time"`
			ControlTime   int64    `json:"control_time" bson:"control_time"`
			OperateReason string   `json:"operate_reason" bson:"operate_reason"`
			Patch         string   `json:"rasp_heartbeat.0.patch" bson:"rasp_heartbeat.0.patch"`
		}
		for cursor.Next(c) {
			var tmpS tmpSearchStruct
			err := cursor.Decode(&tmpS)
			if err != nil {
				continue
			}
			raspProcessVuln := RaspProcessVuln{
				AgentId:     tmpS.AgentId,
				VulnId:      tmpS.VulnId,
				VulnName:    tmpS.TitleCn,
				Pid:         tmpS.Pid,
				Cmd:         tmpS.Cmd,
				CveId:       tmpS.Cve,
				Tag:         tmpS.Tag,
				Level:       levelMap[tmpS.Severity],
				CreateTime:  tmpS.CreateTime,
				UpdateTime:  tmpS.UpdateTime,
				ControlTime: tmpS.ControlTime,
			}
			if tmpS.Patch == "" {
				raspProcessVuln.Status = RaspVulnUnSafe
			} else {
				raspProcessVuln.Status = RaspVulnHotFix
			}

			model := mongo.NewInsertOneModel().SetDocument(raspProcessVuln)
			raspProcessWrites = append(raspProcessWrites, model)
		}

		// 清空历史数据
		raspVulnProcessCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspVulnProcess)

		_, err := raspVulnProcessCol.DeleteMany(c, bson.M{})
		if err != nil {
			ylog.Errorf("Delete error", err.Error())
		}
		time.Sleep(1)

		// 更新漏洞数据
		writeOption := &options.BulkWriteOptions{}
		writeOption.SetOrdered(false)
		_, err = raspVulnProcessCol.BulkWrite(c, raspProcessWrites, writeOption)
		if err != nil {
			return
		}
	}

	if calcuType == "crontab" {
		timer := time.NewTicker(time.Minute * time.Duration(30))
		for {
			select {
			case <-timer.C:
				lockSuccess, err := infra.Grds.SetNX(context.Background(), RaspSyncLock, 1, time.Minute*time.Duration(5)).Result()
				if err != nil || !lockSuccess {
					return
				} else {
					syncFunc()
					_, err := infra.Grds.Del(context.Background(), RaspSyncLock).Result()
					if err != nil {
						continue
					}
				}
			}
		}
	} else if calcuType == "once" {
		lockSuccess, err := infra.Grds.SetNX(context.Background(), RaspSyncLock, 1, time.Minute*time.Duration(5)).Result()
		if err != nil || !lockSuccess {
			return
		} else {
			syncFunc()
			_, err := infra.Grds.Del(context.Background(), RaspSyncLock).Result()
			if err != nil {
				return
			}
		}
	}
}
