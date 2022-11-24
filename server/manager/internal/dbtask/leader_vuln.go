package dbtask

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/muesli/cache2go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PkgInfo struct {
	AgentId       string `json:"agent_id" bson:"agent_id"`
	PackageSeq    string `json:"package_seq" bson:"package_seq"`
	Type          string `json:"type" bson:"type"`
	Token         string `json:"token" bson:"token"`
	Name          string `json:"name" bson:"name"`
	Version       string `json:"sversion" bson:"version"`
	Source        string `json:"source" bson:"source"`
	Status        string `json:"status" bson:"status"`
	Vendor        string `json:"vendor" bson:"vendor"`
	Cmdline       string `json:"cmdline" bson:"cmdline"`
	Pid           string `json:"pid" bson:"pid"`
	Path          string `json:"path" bson:"path"`
	ContainerName string `json:"container_name" bson:"container_name"`
	ContainerId   string `json:"container_id" bson:"container_id"`
}

type AgentVulnSoftInfo struct {
	AgentId        string `json:"agent_id" bson:"agent_id"`
	VulnId         int64  `json:"vuln_id" bson:"vuln_id"`
	Type           string `json:"type" bson:"type"`
	PackageName    string `json:"software_name" bson:"package_name"`
	PackageVersion string `json:"software_version" bson:"package_version"`
	PackageSource  string `json:"software_source" bson:"package_source"`
	PackagePath    string `json:"software_path" bson:"package_path"`
	ContainerName  string `json:"container_name" bson:"container_name"`
	ContainerId    string `json:"container_id" bson:"container_id"`
	Cmdline        string `json:"cmdline" bson:"cmdline"`
	UpdateTime     int64  `json:"update_time" bson:"update_time"`
	PidList        []struct {
		Pid string `json:"pid" bson:"pid"`
		Cmd string `json:"cmd" bson:"cmd"`
	} `json:"pid_list" bson:"pid_list"`
}
type AgentVulnInfo struct {
	AgentId       string `json:"agent_id" bson:"agent_id"`
	VulnId        int64  `json:"vuln_id" bson:"vuln_id"`
	CveId         string `json:"cve_id" bson:"cve_id"`
	Status        string `json:"status" bson:"status"`
	Level         string `json:"level" bson:"level"`
	CreateTime    int64  `json:"create_time" bson:"create_time"`
	UpdateTime    int64  `json:"update_time" bson:"update_time"`
	ControlTime   int64  `json:"control_time" bson:"control_time"`
	DropStatus    string `json:"drop_status" bson:"drop_status"`
	Action        string `json:"action" bson:"action"`
	OperateReason string `json:"operate_reason" bson:"operate_reason"`
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

type VulnInfoLess struct {
	Id            int64  `json:"id" bson:"id"`
	PublishedTime int64  `json:"published_time" bson:"published_time"`
	Severity      string `json:"severity" bson:"severity"`
	Cve           string `json:"cve" bson:"cve"`
	VulnNameEn    string `json:"vuln_name_en" bson:"title_en"`
	Action        string `json:"action" bson:"action"`
	Score         int64
}

type CpeCacheStruct struct {
	VulnIdList []int64
}
type VulnCacheStruct struct {
	VulnInfoList []VulnInfoLess
}

const (
	VulnStatusUnProcessed = "unprocessed"

	VulnStatusIgnored = "ignored"
	VulnDropStatusUse = "using"

	VulnActionBlock = "block"

	CacheTimeout     = 24 * time.Hour
	VulnCacheTimeout = 24 * time.Hour
	MuchVulnAgent    = 2000
)

var (
	CpeCache          *cache2go.CacheTable
	VulnCache         *cache2go.CacheTable
	IfLargeAgentCache *cache2go.CacheTable
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
	for vulnId := range vulnIdMap {
		cpeCacheStruct.VulnIdList = append(cpeCacheStruct.VulnIdList, vulnId)
	}

	// 将数据存入本地缓存
	CpeCache.Add(cpeKey, CacheTimeout, cpeCacheStruct)

	return cpeCacheStruct.VulnIdList
}

// 格式化包名版本
func formatNameVersion(pkgInfo PkgInfo) (retPkgInfo PkgInfo) {

	retPkgInfo.Name = pkgInfo.Name
	retPkgInfo.Version = pkgInfo.Version
	retPkgInfo.AgentId = pkgInfo.AgentId
	retPkgInfo.PackageSeq = pkgInfo.PackageSeq

	switch pkgInfo.Type {
	case "dpkg":
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
		if strings.Contains(retPkgInfo.Version, ":") {
			retPkgInfo.Version = retPkgInfo.Version[strings.Index(retPkgInfo.Version, ":")+1:]
		}

	case "jar":
		if strings.Contains(pkgInfo.Name, "-") {
			retPkgInfo.Name = pkgInfo.Name[:strings.Index(pkgInfo.Name, "-")]
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
		} else if !unicode.IsNumber(r) && r != '.' {
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
		} else if !unicode.IsNumber(r) && r != '.' {
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
	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {

		}
	}(cur, ctx)
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
		if cpeInfo.VersionEndExcluding != "" && compareVersion(pkgInfo.Version, ">=", cpeInfo.VersionEndExcluding) {
			continue
		}
		if cpeInfo.VersionEndIncluding != "" && compareVersion(pkgInfo.Version, ">", cpeInfo.VersionEndIncluding) {

			continue
		}
		if cpeInfo.VersionStartExcluding != "" && compareVersion(pkgInfo.Version, "<=", cpeInfo.VersionStartExcluding) {
			continue
		}
		if cpeInfo.VersionStartIncluding != "" && compareVersion(pkgInfo.Version, "<", cpeInfo.VersionStartIncluding) {
			continue
		}

		// 命中版本范围
		var vulnInfo AgentVulnInfo
		vulnInfo.VulnId = cpeInfo.VulnId
		vulnIdMap[vulnInfo.VulnId] = ""
	}
	return vulnIdMap
}

// 过滤命中的漏洞列表
func FileterVuln(vulnIdList []int64) (retVulnInfoList []VulnInfoLess) {
	if len(vulnIdList) == 0 {
		return
	}
	c := context.Background()
	hitMax := 7 // 单个软件最大命中漏洞数

	// 普通漏洞匹配三年
	recentTimeStamp3 := time.Date(time.Now().Year()-3, time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Local).Unix()

	// 获取主机数量，如果主机数超过5000，只保留高可利用漏洞
	var agentNum int64
	res, err := IfLargeAgentCache.Value("if_large_agent")
	if err != nil {
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		agentNum, err = collection.CountDocuments(context.Background(), bson.M{"last_heartbeat_time": bson.M{"$gte": time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}})
		if err == nil {
			IfLargeAgentCache.Add("if_large_agent", CacheTimeout, agentNum)
		}
	} else {
		agentNum = res.Data().(int64)
	}

	// 通过漏洞时间和风险等级保留漏洞
	vulnInfoCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnInfoCollection)
	findOption := options.Find().SetProjection(bson.M{"id": 1, "published_time": 1, "severity": 1, "cve": 1, "action": 1})
	cur, _ := vulnInfoCol.Find(c, bson.M{"id": bson.M{"$in": vulnIdList}}, findOption)
	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {

		}
	}(cur, c)

	vulnInfoList := make([]VulnInfoLess, 0)
	for cur.Next(c) {
		var v VulnInfoLess
		err := cur.Decode(&v)
		if err != nil {
			continue
		}
		if strings.Contains(v.VulnNameEn, "mac os") {
			continue
		}
		intSeverity, _ := strconv.ParseInt(v.Severity, 10, 64)
		if v.Action == VulnActionBlock {
			intSeverity = 6
		} else if agentNum > MuchVulnAgent {
			continue
		} else if v.PublishedTime < recentTimeStamp3 {
			continue
		}
		v.Score = intSeverity*10000000000 + v.PublishedTime
		vulnInfoList = append(vulnInfoList, v)
	}
	if len(vulnInfoList) > hitMax {
		sort.Slice(vulnInfoList, func(i int, j int) bool {
			return vulnInfoList[i].Score > vulnInfoList[j].Score
		})
		vulnInfoList = vulnInfoList[:hitMax]
	}

	for _, vulnInfo := range vulnInfoList {
		retVulnInfoList = append(retVulnInfoList, vulnInfo)
	}
	return
}

// 处理软件包列表，返回需要处理的mongo语句列表
func DealPkgList(pkgInfoList []PkgInfo) []mongo.WriteModel {
	var writes []mongo.WriteModel
	c := context.Background()
	levelMap := map[string]string{
		"1": "low",
		"2": "low",
		"3": "mid",
		"4": "high",
		"5": "danger",
	}
	agentId := pkgInfoList[0].AgentId

	// 匹配cpe，获取漏洞列表
	newVulnInfoMap := make(map[int64]AgentVulnInfo)
	newVulnSoftMap := make(map[int64][]AgentVulnSoftInfo)
	for _, pkgInfo := range pkgInfoList {
		var vulnInfoList []VulnInfoLess

		// 查看是否在漏洞缓存，生成命中漏洞列表：vulnInfoList
		vulnKey := pkgInfo.Name + "--" + pkgInfo.Version + "--" + pkgInfo.Vendor
		res, err := VulnCache.Value(vulnKey)
		if err == nil {
			vulnInfoList = res.Data().(VulnCacheStruct).VulnInfoList
		} else {
			newPkgInfo := formatNameVersion(pkgInfo)
			vulnIdList := CpeSearch(newPkgInfo)
			vulnInfoList = FileterVuln(vulnIdList)
			var vulnCacheStruct VulnCacheStruct
			vulnCacheStruct.VulnInfoList = vulnInfoList
			VulnCache.Add(vulnKey, VulnCacheTimeout, vulnCacheStruct)
		}

		for _, vulnInfo := range vulnInfoList {
			// 添加漏洞自身内容
			var agentVulnInfo AgentVulnInfo
			agentVulnInfo.AgentId = pkgInfo.AgentId
			agentVulnInfo.VulnId = vulnInfo.Id
			agentVulnInfo.CreateTime = vulnInfo.PublishedTime
			agentVulnInfo.CveId = vulnInfo.Cve
			agentVulnInfo.Level = levelMap[vulnInfo.Severity]
			agentVulnInfo.Action = vulnInfo.Action
			newVulnInfoMap[vulnInfo.Id] = agentVulnInfo

			// 添加漏洞命中软件内容
			agentVulnSoftInfo := AgentVulnSoftInfo{
				AgentId:        pkgInfo.AgentId,
				VulnId:         vulnInfo.Id,
				Type:           pkgInfo.Type,
				PackageName:    pkgInfo.Name,
				PackageVersion: pkgInfo.Version,
				UpdateTime:     time.Now().Unix(),
				ContainerName:  pkgInfo.ContainerName,
				ContainerId:    pkgInfo.ContainerId,
				PackagePath:    pkgInfo.Path,
			}

			if pkgInfo.Pid != "" {
				pidInfo := struct {
					Pid string `json:"pid" bson:"pid"`
					Cmd string `json:"cmd" bson:"cmd"`
				}{
					Pid: pkgInfo.Pid,
					Cmd: pkgInfo.Cmdline,
				}
				agentVulnSoftInfo.PidList = append(agentVulnSoftInfo.PidList, pidInfo)
			}
			if pkgInfo.Type == "dpkg" {
				agentVulnSoftInfo.PackageSource = pkgInfo.Source + "(dpkg)"
			} else {
				agentVulnSoftInfo.PackageSource = pkgInfo.Type
			}
			newVulnSoftMap[vulnInfo.Id] = append(newVulnSoftMap[vulnInfo.Id], agentVulnSoftInfo)
		}
	}

	// 从mongo获取当前主机的老漏洞列表: oldVulnInfoMap
	oldVulnInfoMap := make(map[int64]AgentVulnInfo)
	agentVulnCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnInfo)
	agentVulnSoftCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentVulnSoftInfo)
	cur, _ := agentVulnCol.Find(c, bson.M{"agent_id": agentId})
	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {

		}
	}(cur, c)
	for cur.Next(c) {
		var vulnInfo AgentVulnInfo
		_ = cur.Decode(&vulnInfo)
		oldVulnInfoMap[vulnInfo.VulnId] = vulnInfo
	}

	// 获取已忽略漏洞的列表: ignoredVulnMap
	ignoredVulnMap := make(map[int64]string)
	vulnHeartCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnHeartBeat)
	cur, _ = vulnHeartCol.Find(c, bson.M{"status": VulnStatusIgnored})
	defer func(cur *mongo.Cursor, ctx context.Context) {
		err := cur.Close(ctx)
		if err != nil {

		}
	}(cur, c)
	type VulnHeartLess struct {
		VulnId        int64  `json:"vuln_id" bson:"vuln_id"`
		Status        string `json:"status" bson:"status"`
		OperateReason string `json:"operate_reason" bson:"operate_reason"`
	}
	for cur.Next(c) {
		var vulnHeart VulnHeartLess
		_ = cur.Decode(&vulnHeart)
		ignoredVulnMap[vulnHeart.VulnId] = vulnHeart.OperateReason
	}

	// 更新主机漏洞状态
	agentVulnSoftWrites := make([]mongo.WriteModel, 0, len(newVulnInfoMap))
	for vulnId, newVulnInfo := range newVulnInfoMap {
		var vulnInfo AgentVulnInfo
		vulnInfo.DropStatus = VulnDropStatusUse
		ifVulnIgnored := false
		operateReason := ""
		if reason, ok := ignoredVulnMap[vulnId]; ok {
			ifVulnIgnored = true
			operateReason = reason
		}

		if oldVulnInfo, ok := oldVulnInfoMap[vulnId]; !ok {
			// 生成新漏洞
			vulnInfo.CreateTime = time.Now().Unix()
			vulnInfo.ControlTime = time.Now().Unix()
			if ifVulnIgnored {
				vulnInfo.Status = VulnStatusIgnored
				vulnInfo.OperateReason = operateReason
			} else {
				vulnInfo.Status = VulnStatusUnProcessed
			}
		} else if oldVulnInfo.Status == VulnStatusUnProcessed {
			vulnInfo.CreateTime = oldVulnInfo.CreateTime
			vulnInfo.ControlTime = oldVulnInfo.ControlTime
			vulnInfo.Status = VulnStatusUnProcessed
		} else {
			model := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"vuln_id": vulnId, "agent_id": agentId}).
				SetUpdate(bson.M{"$set": bson.M{"update_time": vulnInfo.UpdateTime}})
			writes = append(writes, model)
			continue
		}
		vulnInfo.AgentId = agentId
		vulnInfo.VulnId = vulnId
		vulnInfo.UpdateTime = time.Now().Unix()
		vulnInfo.CveId = newVulnInfo.CveId
		vulnInfo.Level = newVulnInfo.Level
		vulnInfo.Action = newVulnInfo.Action

		model := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"vuln_id": vulnId, "agent_id": vulnInfo.AgentId}).
			SetUpdate(bson.M{"$set": vulnInfo}).
			SetUpsert(true)
		writes = append(writes, model)

		// 更新漏洞软件表
		for _, agentVulnSoftInfo := range newVulnSoftMap[vulnId] {
			insertModel := mongo.NewUpdateOneModel().
				SetFilter(bson.M{"agent_id": agentVulnSoftInfo.AgentId, "vuln_id": agentVulnSoftInfo.VulnId, "package_name": agentVulnSoftInfo.PackageName}).
				SetUpdate(bson.M{"$set": agentVulnSoftInfo}).
				SetUpsert(true)
			agentVulnSoftWrites = append(agentVulnSoftWrites, insertModel)
		}
	}

	// 更新漏洞软件表
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	_, err := agentVulnSoftCol.BulkWrite(context.Background(), agentVulnSoftWrites, writeOption)
	if err != nil {
		ylog.Errorf("BulkWrite error", err.Error())
	}

	// 更新主机漏洞任务状态
	vulnTaskCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.VulnTaskStatus)
	_, err = vulnTaskCol.UpdateOne(c,
		bson.M{"agent_id": agentId},
		bson.M{"$set": bson.M{"status": "finished"}})
	if err != nil {
		ylog.Errorf("UpdateOne error", err.Error())
	}

	return writes
}

type leaderVulnWriter struct {
	queue chan []PkgInfo
}

func (w *leaderVulnWriter) Init() {
	w.queue = make(chan []PkgInfo, channelSize)
	CpeCache = cache2go.Cache("cpeCache")
	VulnCache = cache2go.Cache("vulnCache")
	IfLargeAgentCache = cache2go.Cache("IfLargeAgentCache")
}

func (w *leaderVulnWriter) Run() {
	for i := 0; i < 8; i++ {
		go w.MyRun()
	}
}

func (w *leaderVulnWriter) MyRun() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(10))
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
				ylog.Errorf("leaderVulnWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("leaderVulnWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := collection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("leaderVulnWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
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
	var v []PkgInfo
	_ = json.Unmarshal(resByre, &v)
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("leaderVulnWriter", "channel is full len %d", len(w.queue))
	}
}
