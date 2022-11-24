package vuln

import (
	"context"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// 开始漏洞检查
func StartDetect(hostList []string, user string) (err error) {
	c := context.Background()
	var agentList []string
	// 下发任务
	if len(hostList) == 0 {
		hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		findOpt := options.FindOptions{}
		findOpt.Projection = bson.M{"agent_id": 1}
		cur, err := hbCol.Find(c, bson.M{"last_heartbeat_time": bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}}, &findOpt)
		if err != nil {
			ylog.Errorf("StartDetect", err.Error())
			return err
		}
		for cur.Next(c) {
			agentId, ok := cur.Current.Lookup("agent_id").StringValueOK()
			if ok {
				agentList = append(agentList, agentId)
			}
		}
	}
	if len(agentList) == 0 {
		return
	}

	taskParam := atask.AgentTask{
		IDList:   agentList,
		TaskName: "collector",
		TaskUser: user,
		Data: def.ConfigRequest{
			Task: def.AgentTaskMsg{
				Name:     "collector",
				DataType: VulnTaskDataType,
			},
		},
	}
	_, _, err = atask.CreateTaskAndRun(&taskParam, atask.TypeAgentTask, 5)

	if err != nil {
		ylog.Errorf("StartDetect", err.Error())
		return
	}

	// 更新任务状态
	taskStatusWrite := make([]mongo.WriteModel, 0, len(agentList))
	for _, agentId := range agentList {
		taskStatusUpdate := bson.M{"$set": bson.M{"status": "running", "last_check_time": time.Now().Unix(), "msg": ""}}

		// 更新漏洞任务状态
		model := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"agent_id": agentId}).
			SetUpdate(taskStatusUpdate).SetUpsert(true)
		taskStatusWrite = append(taskStatusWrite, model)
	}

	// 更新整个漏洞检查状态
	if len(hostList) == 0 {
		groupStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnStatus)
		_, err := groupStatusCol.UpdateOne(c, bson.M{"id": 0},
			bson.M{"$set": bson.M{"status": "running", "last_check_time": time.Now().Unix()}}, (&options.UpdateOptions{}).SetUpsert(true))
		if err != nil {
			ylog.Errorf("Update error", err.Error())
		}
	}

	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)

	// 更新主机任务状态
	taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnTaskStatus)
	_, err = taskStatusCol.BulkWrite(c, taskStatusWrite, writeOption)
	if err != nil {
		ylog.Errorf("BulkWrite error", err.Error())
	}

	// 更新主机漏洞信息,删除旧的漏洞数据
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	agentVulnFilter := make(map[string]interface{})
	agentVulnFilter["agent_id"] = common.MongoInside{Inside: agentList}
	agentVulnFilter["status"] = common.MongoNinside{Value: []string{VulnStatusIgnored, VulnStatusProcessed}}
	agentVulnFilter["drop_status"] = VulnDropStatusDrop
	cur, _ := agentVulnCol.Find(c, agentVulnFilter)
	agentVulnSoftCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnSoftInfo)
	agentVulnSoftWrites := make([]mongo.WriteModel, 0, 0)
	for cur.Next(c) {
		var agentVulnInfo AgentVulnInfo
		err := cur.Decode(&agentVulnInfo)
		if err != nil {
			continue
		}
		insertModel := mongo.NewDeleteManyModel().
			SetFilter(bson.M{"agent_id": agentVulnInfo.AgentId, "vuln_id": agentVulnInfo.VulnId})
		agentVulnSoftWrites = append(agentVulnSoftWrites, insertModel)
	}
	if len(agentVulnSoftWrites) > 0 {
		_, err := agentVulnSoftCol.BulkWrite(context.Background(), agentVulnSoftWrites, writeOption)
		if err != nil {
			ylog.Errorf("BulkWrite error", err.Error())
		}
	}
	_, err = agentVulnCol.DeleteMany(c, agentVulnFilter)
	if err != nil {
		ylog.Errorf("Delete error", err.Error())
	}

	agentVulnFilter["drop_status"] = VulnDropStatusReserve
	_, err = agentVulnCol.UpdateMany(c, agentVulnFilter, bson.M{"$set": bson.M{"drop_status": VulnDropStatusDrop}})
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}
	agentVulnFilter["drop_status"] = VulnDropStatusUse
	_, err = agentVulnCol.UpdateMany(c, agentVulnFilter, bson.M{"$set": bson.M{"drop_status": VulnDropStatusReserve}})
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}

	// 更新主机心跳漏洞数量
	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	hbFilter := make(map[string]interface{})
	hbFilter["agent_id"] = common.MongoInside{Inside: agentList}
	updateQuery := bson.M{"$set": bson.M{"risk.vuln": 0}}
	_, err = hbCol.UpdateMany(c, hbFilter, updateQuery)
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}

	return
}
