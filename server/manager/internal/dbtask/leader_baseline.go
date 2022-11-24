package dbtask

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/muesli/cache2go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AgentBaseline struct {
	AgentId  string       `json:"agent_id" bson:"agent_id"`
	Data     BaselineInfo `json:"data" bson:"data"`
	DataType string       `json:"data_type" bson:"data_type"`
}

type BaselineInfo struct {
	BaselineId      int         `json:"baseline_id" bson:"baseline_id"`
	BaselineVersion string      `json:"baseline_version" bson:"baseline_version"`
	Status          string      `json:"status" bson:"status"`
	Msg             string      `json:"msg" bson:"msg"`
	CheckList       []CheckInfo `json:"check_list" bson:"check_list"`
}

type CheckInfo struct {
	BaselineId    int    `yaml:"baseline_id" bson:"baseline_id" json:"baseline_id"`
	CheckId       int    `yaml:"check_id" bson:"check_id" json:"check_id"`
	BaselineCheck string `yaml:"baseline_check" bson:"baseline_check" json:"baseline_check"`
	Type          string `yaml:"type" bson:"type" json:"type"`
	Title         string `yaml:"title" bson:"title" json:"title"`
	Description   string `yaml:"description" bson:"description" json:"description"`
	Solution      string `yaml:"solution" bson:"solution" json:"solution"`
	Security      string `yaml:"security" bson:"security" json:"security"`
	TitleCn       string `yaml:"title_cn" bson:"title_cn" json:"title_cn"`
	TypeCn        string `yaml:"type_cn" bson:"type_cn" json:"type_cn"`
	DescriptionCn string `yaml:"description_cn" bson:"description_cn" json:"description_cn"`
	SolutionCn    string `yaml:"solution_cn" bson:"solution_cn" json:"solution_cn"`
	UpdateTime    int64  `yaml:"update_time" bson:"update_time" json:"update_time"`

	Result int    `json:"result" bson:"result"`
	Msg    string `json:"msg" bson:"msg"`
}

type BaselineCheckInfo struct {
	CheckId       int    `json:"check_id" bson:"check_id"`
	Type          string `json:"type" bson:"type"`
	Title         string `json:"title" bson:"title"`
	Description   string `json:"description" bson:"description"`
	Solution      string `json:"solution" bson:"solution"`
	Security      string `json:"security" bson:"security"`
	TitleCn       string `json:"title_cn" bson:"title_cn"`
	TypeCn        string `json:"type_cn" bson:"type_cn"`
	DescriptionCn string `json:"description_cn" bson:"description_cn"`
	SolutionCn    string `json:"solution_cn" bson:"solution_cn"`
}

type AgentBaselineInfo struct {
	AgentId         string `json:"agent_id" bson:"agent_id"`
	BaselineId      int    `json:"baseline_id" bson:"baseline_id"`
	BaselineVersion string `json:"baseline_version" bson:"baseline_version"`
	CheckId         int    `json:"check_id" bson:"check_id"`
	Type            string `json:"type" bson:"type"`
	CheckName       string `json:"check_name" bson:"check_name"`
	Description     string `json:"description" bson:"description"`
	Solution        string `json:"solution" bson:"solution"`
	TypeCn          string `json:"type_cn" bson:"type_cn"`
	CheckNameCn     string `json:"check_name_cn" bson:"check_name_cn"`
	DescriptionCn   string `json:"description_cn" bson:"description_cn"`
	SolutionCn      string `json:"solution_cn" bson:"solution_cn"`
	CheckLevel      string `json:"check_level" bson:"check_level"`

	Status       string   `json:"status" bson:"status"`
	CreateTime   int64    `json:"create_time" bson:"create_time"`
	UpdateTime   int64    `json:"update_time" bson:"update_time"`
	IfWhite      bool     `json:"if_white" bson:"if_white"`
	WhiteReason  string   `json:"white_reason" bson:"white_reason"`
	ErrReason    string   `json:"err_reason" bson:"err_reason"`
	TaskStatus   string   `json:"task_status" bson:"task_status"`
	Hostname     string   `json:"hostname" bson:"hostname"`
	Tags         []string `json:"tags" bson:"tags"`
	ExtranetIpv4 []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	IntranetIpv4 []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
}

// 基线策略组状态
type BaselineGroupStatus struct {
	GroupId       int    `json:"group_id" bson:"group_id"`
	BaselineList  []int  `json:"baseline_list" bson:"baseline_list"`
	LastCheckTime int64  `json:"last_check_time" bson:"last_check_time"`
	Status        string `json:"status" bson:"status"`
}

// 基线状态
type BaselineStatus struct {
	BaselineId    int    `json:"baseline_id" bson:"baseline_id"`
	BaselineName  string `json:"baseline_name" bson:"baseline_name"`
	CheckNum      int    `json:"check_num" bson:"check_num"`
	LastCheckTime int64  `json:"last_check_time" bson:"last_check_time"`
	Status        string `json:"status" bson:"status"`
}

// 基线主机任务状态
type BaselineTaskStatus struct {
	AgentId       string   `json:"agent_id" bson:"agent_id"`
	BaselineId    int      `json:"baseline_id" bson:"baseline_id"`
	LastCheckTime int64    `json:"last_check_time" bson:"last_check_time"`
	HighRiskNum   int      `json:"high_risk_num" bson:"high_risk_num"`
	MediumRiskNum int      `json:"medium_risk_num" bson:"medium_risk_num"`
	LowRiskNum    int      `json:"low_risk_num" bson:"low_risk_num"`
	PassNum       int      `json:"pass_num" bson:"pass_num"`
	Status        string   `json:"status" bson:"status"`
	Msg           string   `json:"msg" bson:"msg"`
	Hostname      string   `json:"hostname" bson:"hostname"`
	Tags          []string `json:"tags" bson:"tags"`
	ExtranetIpv4  []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	IntranetIpv4  []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
}

// agent缓存结构体
type AgentCacheStruct struct {
	AgentId      string   `json:"agent_id" bson:"agent_id"`
	Hostname     string   `json:"hostname" bson:"hostname"`
	Tags         []string `json:"tags" bson:"tags"`
	ExtranetIpv4 []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	IntranetIpv4 []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
}

const (
	BaselineStatusPassed = "passed"
	BaselineStatusFailed = "failed"
	BaselineStatusError  = "error"
	checkCacheTimeout    = 1 * time.Hour
	highLevel            = "high"
	mediumLevel          = "mid"
	lowLevel             = "low"
)

var (
	agentCache *cache2go.CacheTable
)

func init() {
	agentCache = cache2go.Cache("agentCache")
}

// 获取agent信息(带缓存机制)
func AgentInfoSearch(agentId string) (agentInfo AgentCacheStruct) {

	// 查看是否在本地缓存中
	res, err := agentCache.Value(agentId)
	if err == nil {
		return res.Data().(AgentCacheStruct)
	}

	// 不在缓存中，查mongo
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)

	err = collection.FindOne(context.Background(), bson.M{"agent_id": agentId}).Decode(&agentInfo)
	if err != nil {
		// 将数据存入本地缓存
		agentCache.Add(agentId, checkCacheTimeout, agentInfo)
	}

	return agentInfo
}

// 处理基线信息，返回需要处理的mongo语句列表
func DealBaselineList(agentBaseline AgentBaseline) []mongo.WriteModel {
	var writes []mongo.WriteModel
	c := context.Background()

	baselineId := agentBaseline.Data.BaselineId
	baselineVersion := agentBaseline.Data.BaselineVersion
	agentId := agentBaseline.AgentId

	// 生成命中检查项详情列表
	newVulnInfoMap := make(map[int]AgentBaselineInfo)
	for _, checkInfo := range agentBaseline.Data.CheckList {
		agentBaselineInfo := AgentBaselineInfo{
			CheckId:         checkInfo.CheckId,
			AgentId:         agentId,
			BaselineId:      baselineId,
			BaselineVersion: baselineVersion,
			CheckLevel:      checkInfo.Security,
			CheckName:       checkInfo.Title,
			Description:     checkInfo.Description,
			Solution:        checkInfo.Solution,
			CheckNameCn:     checkInfo.TitleCn,
			TypeCn:          checkInfo.TypeCn,
			DescriptionCn:   checkInfo.DescriptionCn,
			SolutionCn:      checkInfo.SolutionCn,
			Type:            checkInfo.Type,
		}

		switch checkInfo.Result {
		case 1:
			agentBaselineInfo.Status = BaselineStatusPassed
			agentBaselineInfo.ErrReason = ""
		case 2:
			agentBaselineInfo.Status = BaselineStatusFailed
			agentBaselineInfo.ErrReason = checkInfo.Msg
		default:
			agentBaselineInfo.Status = BaselineStatusError
			switch checkInfo.Result {
			case -2:
				agentBaselineInfo.ErrReason = "主机中的配置文件不规范，无法获取检查信息"
			case -3:
				agentBaselineInfo.ErrReason = "文件读取失败"
			default:
				agentBaselineInfo.ErrReason = checkInfo.Msg
			}
		}

		agentInfo := AgentInfoSearch(agentId)
		agentBaselineInfo.Hostname = agentInfo.Hostname
		agentBaselineInfo.Tags = agentInfo.Tags
		agentBaselineInfo.IntranetIpv4 = agentInfo.IntranetIpv4
		agentBaselineInfo.ExtranetIpv4 = agentInfo.ExtranetIpv4
		newVulnInfoMap[checkInfo.CheckId] = agentBaselineInfo
	}

	// 从mongo获取当前主机的该基线老漏洞列表
	oldVulnInfoMap := make(map[int]AgentBaselineInfo)
	agentBaselineCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	cur, _ := agentBaselineCol.Find(c, bson.M{"agent_id": agentId, "baseline_id": baselineId})
	defer func() {
		_ = cur.Close(c)
	}()
	for cur.Next(c) {
		var baselineInfo AgentBaselineInfo
		_ = cur.Decode(&baselineInfo)
		oldVulnInfoMap[baselineInfo.CheckId] = baselineInfo
	}

	// 因为新增了检查项任务，暂时不删除多余的漏洞
	// 生成需要删除的漏洞
	//var delCheckList []int
	//for checkId, _ := range oldVulnInfoMap {
	//	if _, ok := newVulnInfoMap[checkId]; !ok {
	//		delCheckList = append(delCheckList, checkId)
	//	}
	//}

	//if len(delCheckList) != 0 {
	//	model := mongo.NewDeleteManyModel().
	//		SetFilter(bson.M{"check_id": bson.M{"$in": delCheckList}, "agent_id": agentBaseline.AgentId, "baseline_id": agentBaseline.Data.BaselineId})
	//	writes = append(writes, model)
	//}

	// 更新/插入基线漏洞
	for checkId, agentbaseInfo := range newVulnInfoMap {

		if oldVulnInfo, ok := oldVulnInfoMap[checkId]; !ok {
			// 生成新漏洞
			agentbaseInfo.CreateTime = time.Now().Unix()
		} else if oldVulnInfo.IfWhite {
			// 如果当前漏洞已加白，不做处理
			continue
		}

		agentbaseInfo.UpdateTime = time.Now().Unix()
		agentbaseInfo.TaskStatus = "finished"
		oldVulnInfoMap[checkId] = agentbaseInfo
		model := mongo.NewUpdateOneModel().
			SetFilter(bson.M{"check_id": checkId, "agent_id": agentId, "baseline_id": baselineId}).
			SetUpdate(bson.M{"$set": agentbaseInfo}).
			SetUpsert(true)
		writes = append(writes, model)
	}

	// 更新该基线最近检查时间
	baselineInfoColl := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaseLineInfoColl)
	_, err := baselineInfoColl.UpdateOne(c,
		bson.M{"baseline_id": baselineId},
		bson.M{"$set": bson.M{"last_check_time": time.Now().Unix()}})
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}

	// 更新基线主机任务状态
	var baselineTaskStatus BaselineTaskStatus
	baselineTaskStatus.BaselineId = baselineId
	baselineTaskStatus.AgentId = agentId
	baselineTaskStatus.LastCheckTime = time.Now().Unix()
	baselineTaskStatus.Status = "finished"
	baselineTaskStatus.Msg = ""
	agentInfo := AgentInfoSearch(agentId)
	baselineTaskStatus.Hostname = agentInfo.Hostname
	baselineTaskStatus.Tags = agentInfo.Tags
	baselineTaskStatus.IntranetIpv4 = agentInfo.IntranetIpv4
	baselineTaskStatus.ExtranetIpv4 = agentInfo.ExtranetIpv4

	for _, vulnInfo := range oldVulnInfoMap {
		if !vulnInfo.IfWhite {
			if vulnInfo.Status == BaselineStatusFailed {
				switch vulnInfo.CheckLevel {
				case highLevel:
					baselineTaskStatus.HighRiskNum++
				case mediumLevel:
					baselineTaskStatus.MediumRiskNum++
				case lowLevel:
					baselineTaskStatus.LowRiskNum++
				}
			} else if vulnInfo.Status == BaselineStatusPassed {
				baselineTaskStatus.PassNum++
			}
		}
	}
	taskStatusCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.BaselineTaskStatus)
	_, err = taskStatusCol.UpdateOne(c,
		bson.M{"agent_id": agentId, "baseline_id": baselineId},
		bson.M{"$set": baselineTaskStatus}, (&options.UpdateOptions{}).SetUpsert(true))
	if err != nil {
		ylog.Errorf("Update error", err.Error())
	}

	return writes
}

type leaderBaselineWriter struct {
	queue chan AgentBaseline
}

func (w *leaderBaselineWriter) Init() {
	w.queue = make(chan AgentBaseline, channelSize)
}

func (w *leaderBaselineWriter) Run() {
	var (
		timer  = time.NewTicker(time.Second * time.Duration(5))
		count  = 0
		writes []mongo.WriteModel
	)

	ylog.Infof("leaderBaselineWriter", "Run")
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentBaselineColl)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	for {
		select {
		case baselineList := <-w.queue:
			mongoList := DealBaselineList(baselineList)
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
				ylog.Errorf("leaderBaselineWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("leaderBaselineWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}

			writes = make([]mongo.WriteModel, 0)
			count = 0
		}

		if count >= 100 {
			res, err := collection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("leaderBaselineWriter_BulkWrite", "error:%s len:%d", err.Error(), len(writes))
			} else {
				ylog.Debugf("leaderBaselineWriter_BulkWrite", "UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writes = make([]mongo.WriteModel, 0)
			count = 0
		}
	}
}

func (w *leaderBaselineWriter) Add(tmp interface{}) {
	resByre, _ := json.Marshal(tmp)
	var v AgentBaseline
	_ = json.Unmarshal(resByre, &v)
	select {
	case w.queue <- v:
	default:
		ylog.Errorf("leaderBaselineWriter", "channel is full len %d", len(w.queue))
	}
}
