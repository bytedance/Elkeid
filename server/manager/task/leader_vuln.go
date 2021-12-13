package task

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PkgInfo struct {
	Name    string `json:"name" bson:"name"`
	Version string `json:"version" bson:"version"`
	Source  string `json:"source" bson:"source"`
	Status  string `json:"status" bson:"status"`
	Vendor  string `json:"vendor" bson:"vendor"`
}

type AgentPkgList struct {
	AgentId  string    `json:"agent_id" bson:"agent_id"`
	Data     []PkgInfo `json:"data" bson:"data"`
	DataType string    `json:"data_type" bson:"data_type"`
}

type AgentVulnInfo struct {
	AgentId        string `json:"agent_id" bson:"agent_id"`
	VulnId         int64  `json:"vuln_id" bson:"vuln_id"`
	CveId          string `json:"cve_id" bson:"cve_id"`
	Status         string `json:"status" bson:"status"`
	Level          string `json:"level" bson:"level"`
	PackageName    string `json:"package_name" bson:"package_name"`
	PackageVersion string `json:"package_version" bson:"package_version"`
	CreateTime     int64  `json:"create_time" bson:"create_time"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
}

const (
	VulnStatusUnProcessed = "unprocessed"
	VulnStatusProcessed   = "processed"
	VulnStatusIgnored     = "ignored"
)

// 格式化包名版本
func FormatNameVersion(pkgInfo PkgInfo) (string, string) {

	// 格式化包名和版本
	var pkgName string
	var pkgVersion string
	pkgName = pkgInfo.Name
	pkgVersion = pkgInfo.Version

	// 如果source不为空，优先使用source字段
	source := pkgInfo.Source
	if source != "" {
		versionStart := strings.Index(source, "(")
		if versionStart != -1 {
			versionEnd := strings.Index(source, ")")
			pkgVersion = source[versionStart+1 : versionEnd]
			pkgName = strings.Trim(source[:versionStart], " ")
		} else {
			pkgName = strings.Trim(source, " ")
		}
	}
	return pkgName, pkgVersion
}

// 处理软件包列表，返回需要处理的mongo语句列表
func DealPkgList(agentPkgList AgentPkgList) []mongo.WriteModel {
	var writes []mongo.WriteModel
	c := context.Background()

	// 匹配cpe，获取新漏洞列表
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CpeInfoCollection)
	newVulnInfoMap := make(map[int64]AgentVulnInfo)
	for _, pkgInfo := range agentPkgList.Data {
		pkgName, pkgVersion := FormatNameVersion(pkgInfo)
		cur, _ := collection.Find(c,
			bson.M{"cpe_product": pkgName, "cpe_version": pkgVersion},
			options.Find().SetProjection(bson.M{"vuln_id": 1}))
		defer cur.Close(c)
		for cur.Next(c) {
			var vulnInfo AgentVulnInfo
			_ = cur.Decode(&vulnInfo)

			vulnInfo.PackageName = pkgInfo.Name
			vulnInfo.PackageVersion = pkgInfo.Version
			newVulnInfoMap[vulnInfo.VulnId] = vulnInfo
		}
	}

	// 从mongo获取当前主机的老漏洞列表
	oldVulnInfoMap := make(map[int64]AgentVulnInfo)
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	cur, _ := collection.Find(c, bson.M{"agent_id": agentPkgList.AgentId})
	defer cur.Close(c)
	for cur.Next(c) {
		var vulnInfo AgentVulnInfo
		_ = cur.Decode(&vulnInfo)
		oldVulnInfoMap[vulnInfo.VulnId] = vulnInfo
	}

	// 生成需要删除的漏洞(保留已处理的漏洞)
	var delVulnList []int64
	for vulnId, vulnInfo := range oldVulnInfoMap {
		if _, ok := newVulnInfoMap[vulnId]; !ok {
			if vulnInfo.Status != VulnStatusProcessed {
				delVulnList = append(delVulnList, vulnId)
			}
		}
	}

	if len(delVulnList) != 0 {
		model := mongo.NewDeleteManyModel().
			SetFilter(bson.M{"vuln_id": bson.M{"$in": delVulnList}, "agent_id": agentPkgList.AgentId})
		writes = append(writes, model)
	}

	// 获取漏洞的cve编号和危险等级
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	newVulnInfoList := make([]int64, len(newVulnInfoMap))
	for k := range newVulnInfoMap {
		newVulnInfoList = append(newVulnInfoList, k)
	}
	findOption := options.Find().SetProjection(bson.M{"id": 1, "cve": 1, "severity": 1})
	cur, _ = collection.Find(c, bson.M{"id": bson.M{"$in": newVulnInfoList}}, findOption)
	defer cur.Close(c)
	type vulnInfoStruct struct {
		Id       int64  `json:"id" bson:"id"`
		Cve      string `json:"cve" bson:"cve"`
		Severity string `json:"severity" bson:"severity"`
	}
	var v vulnInfoStruct
	vulnInfoMap := make(map[int64]vulnInfoStruct)
	for cur.Next(c) {
		_ = cur.Decode(&v)
		vulnInfoMap[v.Id] = v
	}

	// 更新，插入漏洞(只关心未处理漏洞)
	unProcessedCount := 0
	levelMap := map[string]string{
		"1": "low",
		"2": "low",
		"3": "mid",
		"4": "high",
		"5": "danger",
	}
	for vulnId, newVulnInfo := range newVulnInfoMap {
		var vulnInfo AgentVulnInfo

		if oldVulnInfo, ok := oldVulnInfoMap[vulnId]; !ok {
			// 生成新漏洞
			vulnInfo.CreateTime = time.Now().Unix()
			vulnInfo.Status = VulnStatusUnProcessed
			unProcessedCount++
		} else if oldVulnInfo.Status == VulnStatusUnProcessed {
			vulnInfo.CreateTime = oldVulnInfo.CreateTime
			vulnInfo.Status = oldVulnInfo.Status
			unProcessedCount++
		} else {
			continue
		}
		vulnInfo.AgentId = agentPkgList.AgentId
		vulnInfo.VulnId = vulnId
		vulnInfo.PackageName = newVulnInfo.PackageName
		vulnInfo.PackageVersion = newVulnInfo.PackageVersion
		vulnInfo.UpdateTime = time.Now().Unix()
		vulnInfo.CveId = vulnInfoMap[vulnId].Cve
		vulnInfo.Level = levelMap[vulnInfoMap[vulnId].Severity]

		model := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"vuln_id": vulnId, "agent_id": vulnInfo.AgentId}).
			SetUpdate(bson.M{"$set": vulnInfo}).
			SetUpsert(true)
		writes = append(writes, model)
	}

	// 计算漏洞总数，并更新到主机心跳包中
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)

	filterQuery := bson.M{"agent_id": agentPkgList.AgentId}
	updateQuery := bson.M{"$set": bson.M{"risk.vuln": unProcessedCount}}
	ahCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	ahCol.UpdateOne(c, filterQuery, updateQuery)

	return writes
}

type leaderVulnWriter struct {
	queue chan AgentPkgList
}

func (w *leaderVulnWriter) Init() {
	w.queue = make(chan AgentPkgList, 4096*256)
}

func (w *leaderVulnWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(5))
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("leaderVulnWriter", "Run")
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case agentPkgList := <-w.queue:
			mongoList := DealPkgList(agentPkgList)
			for _, mongoModel := range mongoList {
				writes = append(writes, mongoModel)
			}
			count += len(mongoList)

		case <-timer.C:
			if count < 1 {
				continue
			}
			res, err := collection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("leaderVulnWriter_BulkWrite", "error:%s len:%s", err.Error(), len(writes))
			} else {
				ylog.Debugf("leaderVulnWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := collection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("leaderVulnWriter_BulkWrite", "error:%s len:%s", err.Error(), len(writes))
			} else {
				ylog.Debugf("leaderVulnWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *leaderVulnWriter) Add(tmp interface{}) {
	resByre, _ := json.Marshal(tmp)
	var v AgentPkgList
	_ = json.Unmarshal(resByre, &v)
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("leaderVulnWriter", "channel is full len %d", len(w.queue))
	}
}
