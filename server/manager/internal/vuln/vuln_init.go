package vuln

import (
	"context"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func InitVuln() {
	go FlushVulnInfo()
	go CalcuVulnList("crontab")
	go WriteVulnProcessList("crontab")
	go InitVulnConf()
	go vulnStatustic()
}

// 初始化漏洞配置
func InitVulnConf() {
	c := context.Background()

	var vulnConf VulnConfUpdate
	vulnConf.Type = VulnConfAutoUpdate

	// 计算最新漏洞日期
	vulnInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	updateStruct := struct {
		UpdateTime int64 `json:"update_time" bson:"update_time"`
	}{}
	err := vulnInfoCol.FindOne(c, bson.M{}, options.FindOne().SetSort(bson.M{"update_time": -1})).Decode(&updateStruct)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	vulnConf.VulnLibVersion = updateStruct.UpdateTime
	cpeInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CpeInfoCollection)
	err = cpeInfoCol.FindOne(c, bson.M{}, options.FindOne().SetSort(bson.M{"update_time": -1})).Decode(&updateStruct)
	if err != nil {
		ylog.Infof("Find error", err.Error())
	}
	vulnConf.CpeLibVersion = updateStruct.UpdateTime

	vulnConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnConfig)
	num, _ := vulnConfCol.CountDocuments(c, bson.M{"type": vulnConf.Type})
	if num > 0 {
		_, err := vulnConfCol.UpdateOne(c, bson.M{"type": vulnConf.Type}, bson.M{"$set": bson.M{"vuln_lib_version": vulnConf.VulnLibVersion, "cpe_lib_version": vulnConf.CpeLibVersion}})
		if err != nil {
			ylog.Errorf("Update error", err.Error())
		}
	} else {
		_, err := vulnConfCol.InsertOne(c, vulnConf)
		if err != nil {
			ylog.Errorf("InsertOne error", err.Error())
		}
	}

	// 初始化7日漏洞统计
	num, _ = vulnConfCol.CountDocuments(c, bson.M{"type": VulnConf7DayList})
	if num == 0 {
		var vulnConf7Day VulnConf7Day
		vulnConf7Day.Type = VulnConf7DayList
		vulnConf7Day.Day7List = make([]VulnDaily, 0)
		_, err := vulnConfCol.InsertOne(c, vulnConf7Day)
		if err != nil {
			ylog.Errorf("InsertOne error", err.Error())
		}
	}

}
