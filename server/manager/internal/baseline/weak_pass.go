package baseline

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	WeakPassDictCollection = "weak_password_dict"
)

// 更新弱口令字典
func UpdateWeakPassList(passwords []string, operator string) error {
	c := context.Background()
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(WeakPassDictCollection)

	// Keep only one document for global dictionary
	filter := bson.M{}
	update := bson.M{
		"$set": bson.M{
			"passwords":   passwords,
			"update_time": time.Now().Unix(),
			"operator":    operator,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err := col.UpdateOne(c, filter, update, opts)
	return err
}

// 获取弱口令字典
func GetWeakPassList() ([]string, error) {
	c := context.Background()
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(WeakPassDictCollection)

	var dict WeakPassDict
	err := col.FindOne(c, bson.M{}).Decode(&dict)
	if err != nil {
		return []string{}, err
	}
	return dict.Passwords, nil
}

// 下发弱口令同步任务
func SyncWeakPassTask(user string) error {
	// 1. Get dictionary
	passwords, err := GetWeakPassList()
	if err != nil {
		return err
	}

	// 2. Prepare task data (compatible with Agent AnalysisBaseline TaskData)
	taskData, _ := json.Marshal(struct {
		BaselineId    int      `json:"baseline_id"`
		WeakPasswords []string `json:"weak_passwords"`
	}{
		BaselineId:    0, // 0 indicates update dictionary only
		WeakPasswords: passwords,
	})

	taskMsg := def.AgentTaskMsg{
		Name:     "baseline",
		Data:     string(taskData),
		DataType: BaselineDataType,
	}

	// 3. Find all active agents
	// Ideally, this should target all agents. For scalability, we might need batching.
	// For now, let's use a simplified approach similar to SendBaselineTask but for all online agents.
	
	// Reusing logic from SendBaselineTask with all online agents
	// Fetch online agents
	c := context.Background()
	hbCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	searchFilter := bson.M{
		"last_heartbeat_time": bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION},
	}
	
	// Batch processing
	batchSize := 1000
	findOpt := options.Find()
	findOpt.SetProjection(bson.M{"agent_id": 1, "plugins": 1})
	findOpt.SetBatchSize(int32(batchSize))
	
	cursor, err := hbCol.Find(c, searchFilter, findOpt)
	if err != nil {
		return err
	}
	
	var batchAgents []string
	for cursor.Next(c) {
		var hb HB
		if err := cursor.Decode(&hb); err != nil {
			continue
		}
		
		// Check if baseline plugin is online
		if isPluginOnline("baseline", hb.Plugin) {
			batchAgents = append(batchAgents, hb.AgentId)
		}
		
		if len(batchAgents) >= batchSize {
			go SendBaselineTask(batchAgents, user, taskMsg)
			batchAgents = make([]string, 0, batchSize)
		}
	}
	
	if len(batchAgents) > 0 {
		go SendBaselineTask(batchAgents, user, taskMsg)
	}
	
	ylog.Infof("SyncWeakPassTask", "Weak password sync task dispatched")
	return nil
}
