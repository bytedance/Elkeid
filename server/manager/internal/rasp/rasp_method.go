package rasp

import (
	"context"
	"encoding/json"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

const (
	raspMethodListStr = "[{\"runtime\":\"Java\",\"class_id\":0,\"method_id\":0,\"class_name\":\"java.lang.ProcessImpl\",\"method_name\":\"start\",\"probe_hook\":\"java.lang.ProcessImpl.start\",\"max_index_count\":5,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"Golang\",\"class_id\":0,\"method_id\":1,\"class_name\":\"os/exec.(*Cmd)\",\"method_name\":\"Start\",\"probe_hook\":\"os/exec.(*Cmd).Start\",\"max_index_count\":2,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":0,\"class_name\":\"process\",\"method_name\":\"passthru\",\"probe_hook\":\"passthru\",\"max_index_count\":1,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":1,\"class_name\":\"process\",\"method_name\":\"system\",\"probe_hook\":\"system\",\"max_index_count\":1,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":2,\"class_name\":\"process\",\"method_name\":\"exec\",\"probe_hook\":\"exec\",\"max_index_count\":1,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":3,\"class_name\":\"process\",\"method_name\":\"shell_exec\",\"probe_hook\":\"shell_exec\",\"max_index_count\":1,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":4,\"class_name\":\"process\",\"method_name\":\"proc_open\",\"probe_hook\":\"proc_open\",\"max_index_count\":1,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":5,\"class_name\":\"process\",\"method_name\":\"popen\",\"probe_hook\":\"popen\",\"max_index_count\":2,\"default_index\":0,\"zh_name\":\"\"},{\"runtime\":\"PHP\",\"class_id\":0,\"method_id\":6,\"class_name\":\"process\",\"method_name\":\"pcntl_exec\",\"probe_hook\":\"pcntl_exec\",\"max_index_count\":2,\"default_index\":0,\"zh_name\":\"\"}]"
	raspMethodVersion = "1.0"
	RaspTypeConfig    = "rasp_config"
)

// 判断当前基线版本，决定是否更新数据库
func judgeraspMethodVersion() bool {
	c := context.Background()
	type Raspconfig struct {
		Type        string `json:"type" bson:"type"`
		RaspVersion string `json:"rasp_version" bson:"rasp_version"`
	}

	var raspConfig Raspconfig
	raspConfig.Type = RaspTypeConfig
	raspConfig.RaspVersion = raspMethodVersion

	// 计算最新漏洞日期
	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)
	num, _ := vulnConfCol.CountDocuments(c, bson.M{"type": RaspTypeConfig})
	if num == 0 {
		_, err := vulnConfCol.InsertOne(c, raspConfig)
		if err != nil {
			ylog.Infof("InsertOne error", err.Error())
		}
		return true
	}

	err := vulnConfCol.FindOne(c, bson.M{"type": RaspTypeConfig}).Decode(&raspConfig)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	if raspConfig.RaspVersion == raspMethodVersion {
		return false
	} else {
		return true
	}
}

// 更新raspMethod数据库
func ChangeRaspMethodDB() {
	// 判断是否需要更新基线配置
	ifUpdate := judgeraspMethodVersion()
	if !ifUpdate {
		return
	}

	// 清空数据库
	raspCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspMethod)
	_, err := raspCol.DeleteMany(context.Background(), bson.M{})
	if err != nil {
		ylog.Errorf("Delete error", err.Error())
	}
	time.Sleep(5 * time.Second)

	// 生成入库数据
	var raspMethodList []RaspMethod
	err = json.Unmarshal([]byte(raspMethodListStr), &raspMethodList)
	if err != nil {
		return
	}

	// 数据入库
	if len(raspMethodList) == 0 {
		return
	}
	writes := make([]mongo.WriteModel, 0, 0)
	for _, raspMethod := range raspMethodList {
		model := mongo.NewInsertOneModel().SetDocument(raspMethod)
		writes = append(writes, model)
	}

	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	_, err = raspCol.BulkWrite(context.Background(), writes, writeOption)
	if err != nil {
		ylog.Errorf("BulkWrite error", err.Error())
	}

	// 将基线版本写入数据库
	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)

	raspConfig := struct {
		Type        string `json:"type" bson:"type"`
		RaspVersion string `json:"rasp_version" bson:"rasp_version"`
	}{
		Type:        RaspTypeConfig,
		RaspVersion: raspMethodVersion,
	}

	_, err = vulnConfCol.UpdateOne(context.Background(),
		bson.M{"type": RaspTypeConfig},
		bson.M{"$set": raspConfig})
	if err != nil {
		return
	}
}
