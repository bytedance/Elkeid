package task

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/muesli/cache2go"
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
	DataType       string `json:"data_type" bson:"data_type"`
	PackageName    string `json:"package_name" bson:"package_name"`
	PackageVersion string `json:"package_version" bson:"package_version"`
	CreateTime     int64  `json:"create_time" bson:"create_time"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
	ControlTime    int64  `json:"control_time" bson:"control_time"`
}

type CpeInfo struct {
	VulnId                int64  `json:"vuln_id" bson:"vuln_id"`
	CpeName               string `json:"cpe_name" bson:"cpe_product"`
	CpeVersion            string `json:"cpe_version" bson:"cpe_version"`
	VersionEndExcluding   string `json:"versionEndExcluding" bson:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding" bson:"versionEndIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding" bson:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding" bson:"versionStartIncluding"`
}

type CpeCacheStruct struct {
	VulnIdList []int64
}

const (
	VulnStatusUnProcessed = "unprocessed"
	VulnStatusProcessed   = "processed"
	VulnStatusIgnored     = "ignored"

	DataTypeDpkg = "5004"
	DataTypeRpm  = "5005"
	DataTypeJar  = "5011"

	CacheTimeout = 24 * time.Hour
)

var (
	CpeCache *cache2go.CacheTable
)

// CPE 查询(带缓存机制)
func CpeSearch(pkgInfo PkgInfo) (vulnIdList []int64) {

	cpeKey := pkgInfo.Name + "-" + pkgInfo.Version + "-" + pkgInfo.Vendor

	// 查看是否在本地缓存中
	res, err := CpeCache.Value(cpeKey)
	if err == nil {
		return res.Data().(CpeCacheStruct).VulnIdList
	}

	// 不在缓存中，查mongo
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CpeInfoCollection)
	vulnIdMap := vulnMatch(pkgInfo, collection)
	var cpeCacheStruct CpeCacheStruct
	for vulnId, _ := range vulnIdMap {
		cpeCacheStruct.VulnIdList = append(cpeCacheStruct.VulnIdList, vulnId)
	}

	// 将数据存入本地缓存
	CpeCache.Add(cpeKey, 24*time.Hour, cpeCacheStruct)

	return cpeCacheStruct.VulnIdList
}

// 格式化包名版本
func formatNameVersion(pkgInfo PkgInfo, dataType string) (retPkgInfo PkgInfo) {

	retPkgInfo.Name = pkgInfo.Name
	retPkgInfo.Version = pkgInfo.Version

	switch dataType {
	case DataTypeDpkg:
		// 如果source不为空，优先使用source字段
		source := pkgInfo.Source
		if source != "" {
			versionStart := strings.Index(source, "(")
			if versionStart != -1 {
				versionEnd := strings.Index(source, ")")
				retPkgInfo.Version = source[versionStart+1 : versionEnd]
				retPkgInfo.Name = strings.Trim(source[:versionStart], " ")
			} else {
				retPkgInfo.Name = strings.Trim(source, " ")
			}
		}
		// 格式化版本号，去掉小版本号
		if strings.Contains(retPkgInfo.Version, "-") {
			retPkgInfo.Version = retPkgInfo.Version[:strings.Index(retPkgInfo.Version, "-")]
		}

	case DataTypeRpm:
		// 如果source不为空，优先使用source字段
		source := pkgInfo.Source
		if source != "" {
			versionStart := strings.Index(source, "(")
			if versionStart != -1 {
				versionEnd := strings.Index(source, ")")
				retPkgInfo.Version = source[versionStart+1 : versionEnd]
				retPkgInfo.Name = strings.Trim(source[:versionStart], " ")
			} else {
				retPkgInfo.Name = strings.Trim(source, " ")
			}
		}

	case DataTypeJar:
		if strings.Contains(pkgInfo.Source, "-") {
			retPkgInfo.Name = pkgInfo.Source[:strings.Index(pkgInfo.Source, "-")]
		} else {
			retPkgInfo.Name = pkgInfo.Source
		}
		retPkgInfo.Vendor = "apache"
	}

	return retPkgInfo
}

// 版本号比较
/* 思路：，。，
1. 将"_-"替换成"."
2. "a-z"替换成0
3. 按照"."进行分割
4. 每一项转换int,进行乘积，例 2.15.1 = 2*100^5 + 15*100^4 + 1*100^3
5. 进行两个int大小的比较
*/
func compareVersion(v1 string, symbol string, v2 string) bool {
	// 双方归一化
	v1_new := []byte(v1)
	v2_new := []byte(v2)
	for i, r := range v1 {
		if r == '_' || r == '-' {
			v1_new[i] = '.'
			continue
		} else if unicode.IsLetter(r) {
			v1_new[i] = '0'
			continue
		} else {
			v1_new[i] = byte(r)
		}
	}
	for i, r := range v2 {
		if r == '_' || r == '-' {
			v2_new[i] = '.'
			continue
		} else if unicode.IsLetter(r) {
			v2_new[i] = '0'
			continue
		} else {
			v2_new[i] = byte(r)
		}
	}

	v1 = string(v1_new)
	v2 = string(v2_new)

	// 版本号数字化
	v1Array := strings.Split(v1, ".")
	v1Sum := float64(0)
	for i, s := range v1Array {
		if i >= 4 {
			break
		}
		if len(s) > 3 {
			s = s[:3]
		}
		s, err := strconv.ParseFloat(s, 64)

		if err != nil {
			continue
		} else {
			v1Sum += s * math.Pow(1000, 4-float64(i))
		}
	}
	v2Array := strings.Split(v2, ".")
	v2Sum := float64(0)
	for i, s := range v2Array {
		if i >= 4 {
			break
		}
		if len(s) > 3 {
			s = s[:3]
		}
		s, err := strconv.ParseFloat(s, 64)

		if err != nil {
			continue
		} else {
			v2Sum += s * math.Pow(1000, 4-float64(i))
		}
	}

	// 比较v1 v2大小
	switch symbol {
	case "<":
		if v1Sum < v2Sum {
			return true
		}
	case ">":
		if v1Sum > v2Sum {
			return true
		}
	case "=":
		if v1Sum == v2Sum {
			return true
		}
	case ">=":
		if v1Sum >= v2Sum {
			return true
		}
	case "<=":
		if v1Sum <= v2Sum {
			return true
		}
	}
	return false
}

// 漏洞匹配
func vulnMatch(pkgInfo PkgInfo, cpeColl *mongo.Collection) (vulnIdMap map[int64]string) {
	ctx := context.Background()
	vulnIdMap = make(map[int64]string)

	// 匹配精准命中的包名版本
	searchFilter := make(map[string]interface{})
	searchFilter["cpe_product"] = pkgInfo.Name
	searchFilter["cpe_version"] = pkgInfo.Version
	if pkgInfo.Vendor != "" {
		searchFilter["cpe_vendor"] = pkgInfo.Vendor
	}

	cur, _ := cpeColl.Find(ctx, searchFilter,
		options.Find().SetProjection(bson.M{"vuln_id": 1}))
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var vulnInfo AgentVulnInfo
		_ = cur.Decode(&vulnInfo)

		vulnIdMap[vulnInfo.VulnId] = ""
	}

	// 通过版本范围，匹配漏洞
	searchFilter = make(map[string]interface{})
	searchFilter["cpe_product"] = pkgInfo.Name
	if pkgInfo.Vendor != "" {
		searchFilter["cpe_vendor"] = pkgInfo.Vendor
	}
	cur, _ = cpeColl.Find(ctx, searchFilter,
		options.Find())

	for cur.Next(ctx) {
		var cpeInfo CpeInfo
		_ = cur.Decode(&cpeInfo)

		// 过滤已命中的漏洞
		if _, ok := vulnIdMap[cpeInfo.VulnId]; ok {
			continue
		}

		// 匹配漏洞大小范围
		if cpeInfo.VersionEndExcluding == "" && cpeInfo.VersionEndIncluding == "" &&
			cpeInfo.VersionStartExcluding == "" && cpeInfo.VersionStartIncluding == "" {
			continue
		}
		if cpeInfo.VersionEndExcluding != "" && compareVersion(pkgInfo.Version, "<=", cpeInfo.VersionEndExcluding) {
			continue
		}
		if cpeInfo.VersionEndIncluding != "" && compareVersion(pkgInfo.Version, ">", cpeInfo.VersionEndIncluding) {

			continue
		}
		if cpeInfo.VersionStartExcluding != "" && compareVersion(pkgInfo.Version, ">=", cpeInfo.VersionEndExcluding) {
			continue
		}
		if cpeInfo.VersionStartIncluding != "" && compareVersion(pkgInfo.Version, "<", cpeInfo.VersionStartIncluding) {
			continue
		}

		// 命中版本范围
		var vulnInfo AgentVulnInfo
		vulnInfo.VulnId = cpeInfo.VulnId
		vulnInfo.PackageName = pkgInfo.Name
		vulnInfo.PackageVersion = pkgInfo.Version
		vulnIdMap[vulnInfo.VulnId] = ""
	}
	return vulnIdMap
}

// 匹配cpe，获取漏洞列表
func GetVulnList(agentPkgList AgentPkgList) (newVulnInfoMap map[int64]AgentVulnInfo) {
	newVulnInfoMap = make(map[int64]AgentVulnInfo)

	// 依次匹配软件包
	for _, pkgInfo := range agentPkgList.Data {

		newPkgInfo := formatNameVersion(pkgInfo, agentPkgList.DataType)
		if newPkgInfo.Name == "openssl" {
			ylog.Infof("DealPkgList", newPkgInfo.Source+newPkgInfo.Version)
		}
		vulnIdList := CpeSearch(newPkgInfo)
		for _, vulnId := range vulnIdList {
			var vulnInfo AgentVulnInfo
			vulnInfo.VulnId = vulnId
			vulnInfo.PackageName = pkgInfo.Name
			vulnInfo.PackageVersion = pkgInfo.Version
			newVulnInfoMap[vulnId] = vulnInfo
		}
	}

	return newVulnInfoMap
}

// 处理软件包列表，返回需要处理的mongo语句列表
func DealPkgList(agentPkgList AgentPkgList) []mongo.WriteModel {
	var writes []mongo.WriteModel
	c := context.Background()

	// 获取当前未处理漏洞总数，用于计算
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	unProcessedCount, _ := collection.CountDocuments(c, bson.M{"agent_id": agentPkgList.AgentId, "status": VulnStatusUnProcessed})

	// 匹配cpe，获取新漏洞列表
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.CpeInfoCollection)
	newVulnInfoMap := make(map[int64]AgentVulnInfo)
	newVulnInfoMap = GetVulnList(agentPkgList)

	// 从mongo获取当前主机的老漏洞列表
	oldVulnInfoMap := make(map[int64]AgentVulnInfo)
	collection = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	cur, _ := collection.Find(c, bson.M{"agent_id": agentPkgList.AgentId, "data_type": agentPkgList.DataType})
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
				unProcessedCount--
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
			unProcessedCount++
			vulnInfo.CreateTime = time.Now().Unix()
			vulnInfo.ControlTime = time.Now().Unix()
			vulnInfo.Status = VulnStatusUnProcessed
		} else if oldVulnInfo.Status == VulnStatusUnProcessed {
			vulnInfo.CreateTime = oldVulnInfo.CreateTime
			vulnInfo.Status = oldVulnInfo.Status
		} else {
			continue
		}
		vulnInfo.AgentId = agentPkgList.AgentId
		vulnInfo.DataType = agentPkgList.DataType
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

	// 更新漏洞总数到主机心跳包中
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
	CpeCache = cache2go.Cache("cpeCache")
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
