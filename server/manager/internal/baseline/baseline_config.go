package baseline

import (
	"context"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/yaml.v2"
	"os"
	"time"
)

const (
	baselineVersion    = "2.0.0.7"
	BaselineTypeConfig = "baseline_config"
)

// 单个检查项信息
type CheckInfo_config struct {
	BaselineId    int    `yaml:"baseline_id" bson:"baseline_id"`
	CheckId       int    `yaml:"check_id" bson:"check_id"`
	Type          string `yaml:"type" bson:"type"`
	Title         string `yaml:"title" bson:"title"`
	Description   string `yaml:"description" bson:"description"`
	Solution      string `yaml:"solution" bson:"solution"`
	Security      string `yaml:"security" bson:"security"`
	TitleCn       string `yaml:"title_cn" bson:"title_cn"`
	TypeCn        string `yaml:"type_cn" bson:"type_cn"`
	DescriptionCn string `yaml:"description_cn" bson:"description_cn"`
	SolutionCn    string `yaml:"solution_cn" bson:"solution_cn"`
	UpdateTime    int64  `yaml:"update_time" bson:"update_time"`
}

// 基线配置文件结构
type BaselineInfo_config struct {
	BaselineId      int                `yaml:"baseline_id" bson:"baseline_id"`
	BaselineVersion string             `yaml:"baseline_version" bson:"baseline_version"`
	BaselineName    string             `yaml:"baseline_name" bson:"baseline_name"`
	BaselineNameEn  string             `yaml:"baseline_name_en" bson:"baseline_name_en"`
	SystemList      []string           `yaml:"system" bson:"system_list"`
	CheckList       []CheckInfo_config `yaml:"check_list" bson:"check_list"`
}

// 基线mongo表结构
type BaselineInfoMongo struct {
	BaselineId      int      `yaml:"baseline_id" bson:"baseline_id"`
	BaselineVersion string   `yaml:"baseline_version" bson:"baseline_version"`
	BaselineName    string   `yaml:"baseline_name" bson:"baseline_name"`
	BaselineNameEn  string   `yaml:"baseline_name_en" bson:"baseline_name_en"`
	SystemList      []string `yaml:"system" bson:"system_list"`
	CheckIdList     []int    `yaml:"check_id_list" bson:"check_id_list"`
	UpdateTime      int64    `yaml:"update_time" bson:"update_time"`
}

// 基线策略组
type BaselineGroupMongo struct {
	GroupId      int                   `bson:"group_id"`
	GroupName    string                `bson:"group_name"`
	GroupNameEn  string                `bson:"group_name_en"`
	BaselineList []BaselineInfo_config `bson:"baseline_list"`
}

// 解析yaml文件
func bindYaml(filePath string, yamlMap interface{}) error {
	var err error
	if f, err := os.Open(filePath); err != nil {
	} else {
		err = yaml.NewDecoder(f).Decode(yamlMap)
		return err
	}
	return err
}

// 将yaml文件信息入到mongo baseline_info表, check_info表
func yaml2Mongo(yamlPath string) {
	c := context.Background()
	time64 := time.Now().Unix()

	// 读取并绑定配置文件
	baselineInfo := new(BaselineInfo_config)
	err := bindYaml(yamlPath, baselineInfo)
	if err != nil {
		fmt.Println("绑定yaml失败")
		fmt.Println(err)
		return
	}

	// 删除历史数据
	baselineInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
	baselineCheckCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineCheckInfoColl)
	baselineStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineStatus)

	_, err = baselineInfoCol.DeleteMany(c, bson.M{"baseline_id": baselineInfo.BaselineId})
	if err != nil {
		ylog.Errorf("Delete error", err.Error())
	}
	_, err = baselineCheckCol.DeleteMany(c, bson.M{"baseline_id": baselineInfo.BaselineId})
	if err != nil {
		ylog.Errorf("Delete error", err.Error())
	}
	_, err = baselineStatusCol.DeleteMany(c, bson.M{"baseline_id": baselineInfo.BaselineId})
	if err != nil {
		ylog.Errorf("Delete error", err.Error())
	}

	// 基线信息存入baseline_info表
	var baselineMongo BaselineInfoMongo
	baselineMongo.BaselineName = baselineInfo.BaselineName
	baselineMongo.BaselineNameEn = baselineInfo.BaselineNameEn
	baselineMongo.BaselineId = baselineInfo.BaselineId
	baselineMongo.BaselineVersion = baselineInfo.BaselineVersion
	baselineMongo.SystemList = baselineInfo.SystemList
	baselineMongo.UpdateTime = time64
	for _, checkInfo := range baselineInfo.CheckList {
		baselineMongo.CheckIdList = append(baselineMongo.CheckIdList, checkInfo.CheckId)
	}

	// 更新mongo数据库。注意，下边语句为upsert，如果filter符合，会覆盖mongo数据库！！！！
	filter := bson.M{"baseline_id": baselineMongo.BaselineId, "baseline_version": baselineMongo.BaselineVersion}
	option := &options.UpdateOptions{}
	option.SetUpsert(true)
	_, err = baselineInfoCol.UpdateOne(c, filter, bson.M{"$set": baselineMongo}, option)

	// 检查项信息存入baseline_check_info表
	for _, checkInfo := range baselineInfo.CheckList {
		checkInfo.BaselineId = baselineInfo.BaselineId
		checkInfo.UpdateTime = time64
		filter := bson.M{"baseline_id": baselineMongo.BaselineId, "baseline_version": baselineMongo.BaselineVersion, "check_id": checkInfo.CheckId}
		_, err := baselineCheckCol.UpdateOne(c, filter, bson.M{"$set": checkInfo}, option)
		if err != nil {
			ylog.Errorf("Update error", err.Error())
		}
	}

	// 新增基线检测状态
	var baselineStatus BaselineStatus
	baselineStatus.BaselineId = baselineInfo.BaselineId
	baselineStatus.BaselineName = baselineInfo.BaselineName
	baselineStatus.BaselineNameEn = baselineInfo.BaselineNameEn
	baselineStatus.CheckNum = len(baselineMongo.CheckIdList)
	baselineStatus.Status = "finished"
	filter = bson.M{"baseline_id": baselineMongo.BaselineId}
	option = &options.UpdateOptions{}
	option.SetUpsert(true)
	_, err = baselineStatusCol.UpdateOne(c, filter, bson.M{"$set": baselineStatus}, option)

}

// 新建默认策略组
func newGroup(baselineGroupMongo BaselineGroupMongo, baselineIdList []int) {

	baselineInfo := new(BaselineInfo_config)
	var groupBaselineInfo BaselineInfo_config
	for _, baselineId := range baselineIdList {
		// 读取并绑定配置文件
		err := bindYaml(fmt.Sprintf("conf/baseline_config/%d.yaml", baselineId), baselineInfo)
		if err != nil {
			fmt.Println("绑定yaml失败")
			fmt.Println(err)
			return
		}
		groupBaselineInfo.BaselineVersion = baselineInfo.BaselineVersion
		groupBaselineInfo.BaselineId = baselineInfo.BaselineId
		groupBaselineInfo.BaselineName = baselineInfo.BaselineName
		groupBaselineInfo.BaselineNameEn = baselineInfo.BaselineNameEn
		baselineGroupMongo.BaselineList = append(baselineGroupMongo.BaselineList, groupBaselineInfo)
	}

	// 存入mongo
	c := context.Background()
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)

	option := &options.UpdateOptions{}
	option.SetUpsert(true)

	_, err := collection.UpdateOne(c, bson.M{"group_id": baselineGroupMongo.GroupId}, bson.M{"$set": baselineGroupMongo}, option)
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}

	// 新建策略组状态信息
	var baselineGroupStatus BaselineGroupStatus
	baselineGroupStatus.GroupId = baselineGroupMongo.GroupId
	baselineGroupStatus.Status = "finished"
	baselineGroupStatus.LastCheckTime = 0
	baselineGroupStatus.BaselineList = baselineIdList
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupStatus)

	_, err = collection.UpdateOne(c, bson.M{"group_id": baselineGroupStatus.GroupId}, bson.M{"$set": baselineGroupStatus}, option)
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}
}

// 判断当前基线版本，决定是否更新数据库
func judgeBaselineVersion() bool {
	c := context.Background()
	type BaselineConfig struct {
		Type            string `json:"type" bson:"type"`
		BaselineVersion string `json:"baseline_version" bson:"baseline_version"`
	}

	// 判断基线配置目录是否存在
	_, err := os.Stat("conf/baseline_config")
	if err != nil {
		return false
	}

	var baselineConfig BaselineConfig
	baselineConfig.Type = BaselineTypeConfig
	baselineConfig.BaselineVersion = baselineVersion

	// 计算最新漏洞日期
	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)
	num, _ := vulnConfCol.CountDocuments(c, bson.M{"type": BaselineTypeConfig})
	if num == 0 {
		_, err := vulnConfCol.InsertOne(c, baselineConfig)
		if err != nil {
			ylog.Errorf("Insert error", err.Error())
		}
		return true
	}

	err = vulnConfCol.FindOne(c, bson.M{"type": BaselineTypeConfig}).Decode(&baselineConfig)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	if baselineConfig.BaselineVersion == baselineVersion {
		return false
	} else {
		return true
	}
}

func ChangeBaselineDB() {
	c := context.Background()
	// 判断是否需要更新基线配置
	ifUpdate := judgeBaselineVersion()
	if !ifUpdate {
		return
	}

	fmt.Println("开始基线表初始化")
	// toB
	yaml2Mongo("conf/baseline_config/1200.yaml")
	yaml2Mongo("conf/baseline_config/1300.yaml")
	yaml2Mongo("conf/baseline_config/1400.yaml")
	yaml2Mongo("conf/baseline_config/5000.yaml")

	fmt.Println("开始初始化策略组")

	groupInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineGroupInfo)
	_, err := groupInfoCol.DeleteMany(c, bson.M{})
	if err != nil {
		ylog.Errorf("Delete error", err.Error())
	}

	var baselineGroupMongo BaselineGroupMongo
	baselineGroupMongo.GroupId = 1
	baselineGroupMongo.GroupName = "linux字节跳动最佳实践扫描策略"
	baselineGroupMongo.GroupNameEn = "default linux policy"
	baselineIdList1 := [...]int{1200, 1300, 1400, 5000}
	newGroup(baselineGroupMongo, baselineIdList1[:])

	// 将基线版本写入数据库
	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)

	baselineConfig := struct {
		Type            string `json:"type" bson:"type"`
		BaselineVersion string `json:"baseline_version" bson:"baseline_version"`
	}{
		Type:            BaselineTypeConfig,
		BaselineVersion: baselineVersion,
	}

	_, err = vulnConfCol.UpdateOne(context.Background(),
		bson.M{"type": BaselineTypeConfig},
		bson.M{"$set": baselineConfig})
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}
}
