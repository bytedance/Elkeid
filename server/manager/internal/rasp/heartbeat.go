package rasp

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"github.com/muesli/cache2go"
	"go.mongodb.org/mongo-driver/bson"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 定时更新rasp配置缓存
var raspConfigMap = make(map[string][]RaspTaskConfig, 0)
var raspConfigIdMap = make(map[string]RaspTaskConfig, 0)
var (
	raspMethodCache *cache2go.CacheTable
)

func RaspConfigCronJob() {
	myFunc := func() {
		defer func() {
			if err := recover(); err != nil {

			}
		}()
		c := context.Background()
		raspConfigMapNew := make(map[string][]RaspTaskConfig, 0)
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspConfig)
		cur, err := collection.Find(c, bson.M{"if_protect": true})
		if err != nil {
			return
		}
		for cur.Next(c) {
			// 格式化

			var raspConfig RaspTaskConfig
			err := cur.Decode(&raspConfig)
			if err != nil {
				continue
			}

			probeConfigList := getProbeMessage(raspConfig)
			for _, probeConfig := range probeConfigList {
				switch probeConfig.MessageType {
				case RaspFilterType:
					raspConfig.FilterUuid = probeConfig.Data.Uuid
				case RaspBlockType:
					raspConfig.BlockUuid = probeConfig.Data.Uuid
				case RaspLimitType:
					raspConfig.LimitUuid = probeConfig.Data.Uuid
				case RaspPatchType:
					raspConfig.PatchUuid = probeConfig.Data.Uuid
				}
			}
			probeConfigJson, err := json.Marshal(probeConfigList)

			raspConfig.TaskStr = string(probeConfigJson)

			raspConfigIdMap[raspConfig.Id.String()] = raspConfig

			raspConfig.EnvJson = make(map[string]string, 0)
			raspConfig.EnvJson["TCE_PSM"] = ""
			raspConfig.EnvJson["TCE_HOST_ENV"] = ""
			for _, envInfo := range raspConfig.EnvList {
				envSp := strings.Split(envInfo, "=")
				if len(envSp) != 2 {
					continue
				}
				raspConfig.EnvJson[envSp[0]] = envSp[1]
			}
			if len(raspConfig.Runtime) == 0 {
				continue
			}
			raspConfigKey := raspConfig.Runtime[0] + "-" + raspConfig.EnvJson["TCE_PSM"] + "-" + raspConfig.EnvJson["TCE_HOST_ENV"]
			if _, ok := raspConfigMapNew[raspConfigKey]; ok {
				raspConfigMapNew[raspConfigKey] = append(raspConfigMapNew[raspConfigKey], raspConfig)
			} else {
				raspConfigMapNew[raspConfigKey] = []RaspTaskConfig{raspConfig}
			}
		}
		raspConfigMap = make(map[string][]RaspTaskConfig, 0)
		raspConfigMap = raspConfigMapNew
	}

	time.Sleep(5 * time.Second) // 为了让mongo句柄先初始化
	configLock.Lock()
	myFunc()
	configLock.Unlock()
	timer := time.NewTicker(time.Minute * time.Duration(10))
	for {
		select {
		case <-timer.C:
			configLock.Lock()
			myFunc()
			configLock.Unlock()
		}
	}
}

// rasp心跳过配置
func raspConfigMatch(raspInfo RaspHbType) (ifMatch bool, retRaspConfig RaspTaskConfig, err error) {
	if _, ok := raspInfo.Env["TCE_PSM"]; !ok {
		raspInfo.Env["TCE_PSM"] = ""
	}
	if _, ok := raspInfo.Env["TCE_HOST_ENV"]; !ok {
		raspInfo.Env["TCE_HOST_ENV"] = ""
	}
	raspConfigKey := raspInfo.Runtime + "-" + raspInfo.Env["TCE_PSM"] + "-" + raspInfo.Env["TCE_HOST_ENV"]
	configLock.Lock()
	raspConfigList, ok := raspConfigMap[raspConfigKey]
	configLock.Unlock()
	if ok {
		// 倒序遍历，取最新一条命中的配置
		for i := len(raspConfigList) - 1; i >= 0; i-- {
			raspConfig := raspConfigList[i]
			if raspConfig.AliveTime > 0 {
				uptimeInt, err := strconv.Atoi(raspInfo.Uptime)
				if err != nil || uptimeInt < raspConfig.AliveTime {
					continue
				}
			}
			if raspConfig.Tag != "" {
				if raspConfig.Tag != raspInfo.Tag {
					continue
				}
			}
			if raspConfig.Cmd != "" {
				ifReg, _ := regexp.MatchString(raspConfig.Cmd, raspInfo.Cmd)
				if !ifReg {
					continue
				}
			}
			if len(raspConfig.IpList) != 0 {
				ifIp := false
				for _, ip2 := range raspInfo.Ipv4List {
					for _, ip1 := range raspConfig.IpList {
						if ip1 == ip2 {
							ifIp = true
							break
						}
					}
				}
				for _, ip2 := range raspInfo.Exv4List {
					for _, ip1 := range raspConfig.IpList {
						if ip1 == ip2 {
							ifIp = true
							break
						}
					}
				}
				if !ifIp {
					continue
				}
			}

			delete(raspConfig.EnvJson, "TCE_PSM")
			delete(raspConfig.EnvJson, "TCE_HOST_ENV")
			if len(raspConfig.EnvJson) > 0 {
				ifEnv := true
				for key, value := range raspConfig.EnvJson {
					if _, ok := raspInfo.Env[key]; !ok {
						ifEnv = false
						break
					} else if raspInfo.Env[key] != value {
						ifEnv = false
						break
					}
				}
				if !ifEnv {
					continue
				}
			}
			retRaspConfig = raspConfig
			return true, retRaspConfig, nil
		}
	}
	return false, retRaspConfig, nil
}

type RaspPluginTask struct {
	Name     string              `json:"name" bson:"name"`
	Commands []RaspPluginCommand `json:"commands" bson:"commands"`
}
type RaspPluginCommand struct {
	Pid          string `json:"pid" bson:"pid"`
	Runtime      string `json:"runtime" bson:"runtime"`
	State        string `json:"state" bson:"state"`
	ProbeMessage string `json:"probe_message" bson:"probe_message"`
}
type ProbeConfig struct {
	MessageType int             `json:"message_type" bson:"message_type"`
	Data        ProbeConfigData `json:"data" bson:"data"`
}
type ProbeConfigData struct {
	Uuid    string              `json:"uuid" bson:"uuid"`
	Blocks  []ProbeConfigBlock  `json:"blocks,omitempty" bson:"blocks"`
	Filters []ProbeConfigFilter `json:"filters,omitempty" bson:"filters"`
	Limits  []ProbeConfigLimit  `json:"limits,omitempty" bson:"limits"`
	Patches []ProbeConfigPatch  `json:"patches,omitempty" bson:"patches"`
}
type ProbeConfigBlock struct {
	ClassId  int                `json:"class_id" bson:"class_id"`
	MethodId int                `json:"method_id" bson:"method_id"`
	Rules    []ProbeConfigRules `json:"rules" bson:"rules"`
}
type ProbeConfigFilter struct {
	ClassId  int                `json:"class_id" bson:"class_id"`
	MethodId int                `json:"method_id" bson:"method_id"`
	Include  []ProbeConfigRules `json:"include" bson:"include"`
	Exclude  []ProbeConfigRules `json:"exclude" bson:"exclude"`
}
type ProbeConfigRules struct {
	Index int    `json:"index" bson:"index"`
	Regex string `json:"regex" bson:"regex"`
}
type ProbeConfigLimit struct {
	ClassId  int `json:"class_id" bson:"class_id"`
	MethodId int `json:"method_id" bson:"method_id"`
	Quota    int `json:"quota" bson:"quota"`
}
type ProbeConfigPatch struct {
	ClassName       string   `json:"class_name" bson:"class_name"`
	Path            string   `json:"path" bson:"path"`
	FileDownloadUrl []string `json:"file_download_url" bson:"file_download_url"`
	SumHash         string   `json:"sum_hash" bson:"sum_hash"`
}

const (
	RaspFilterType = 6
	RaspBlockType  = 7
	RaspLimitType  = 8
	RaspPatchType  = 9
)

func md5Str(origin string) string {
	m := md5.New()
	m.Write([]byte(origin))
	return hex.EncodeToString(m.Sum(nil))
}

// 生成过滤阻断配置
func getProbeMessage(raspConfig RaspTaskConfig) (probeConfigList []ProbeConfig) {
	c := context.Background()
	raspMethodCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspMethod)
	ifHasConfig := false

	var blockProbeConfig ProbeConfig
	blockProbeConfig.MessageType = RaspBlockType
	blockProbeConfig.Data.Blocks = make([]ProbeConfigBlock, 0)
	// 添加阻断block数据
	if len(raspConfig.Block) != 0 {
		ifHasConfig = true
		hash := ""
		funcMap := make(map[string]ProbeConfigBlock, 0)
		for _, raspConfigRule := range raspConfig.Block {
			for _, funName := range raspConfigRule.HookFunc {
				var probeConfigBlock ProbeConfigBlock
				var raspMethod RaspMethod

				cacheItem, err := raspMethodCache.Value(funName)
				if err != nil {
					err := raspMethodCol.FindOne(c, bson.M{"probe_hook": funName}).Decode(&raspMethod)
					if err != nil {
						continue
					}
					raspMethodCache.Add(funName, raspCacheTimeout, raspMethod)
				} else {
					raspMethod = cacheItem.Data().(RaspMethod)
				}

				probeConfigBlock.MethodId = raspMethod.MethodId
				probeConfigBlock.ClassId = raspMethod.ClassId

				if len(raspConfigRule.Rules) != 0 {
					for _, rule := range raspConfigRule.Rules {
						var probeConfigRules ProbeConfigRules
						probeConfigRules.Index = raspConfigRule.HookParam
						probeConfigRules.Regex = rule.Rule
						if rule.Type == "include" {
							probeConfigBlock.Rules = append(probeConfigBlock.Rules, probeConfigRules)
							hash += strconv.Itoa(probeConfigRules.Index) + probeConfigRules.Regex
						}
					}
				}

				// 如果该方法已存在，合并rules
				if probeConfigRules, ok := funcMap[funName]; ok {
					for _, rules := range probeConfigBlock.Rules {
						probeConfigRules.Rules = append(probeConfigRules.Rules, rules)
					}
					funcMap[funName] = probeConfigRules
				} else {
					funcMap[funName] = probeConfigBlock
				}
				hash += strconv.Itoa(probeConfigBlock.MethodId) + strconv.Itoa(probeConfigBlock.ClassId)
			}
		}
		for _, probeConfigBlock := range funcMap {
			blockProbeConfig.Data.Blocks = append(blockProbeConfig.Data.Blocks, probeConfigBlock)
		}
		blockProbeConfig.Data.Uuid = md5Str(hash)
	}
	probeConfigList = append(probeConfigList, blockProbeConfig)

	var filterProbeConfig ProbeConfig
	filterProbeConfig.MessageType = RaspFilterType
	filterProbeConfig.Data.Filters = make([]ProbeConfigFilter, 0)
	if len(raspConfig.Filter) != 0 {
		ifHasConfig = true
		hash := ""
		funcMap := make(map[string]ProbeConfigFilter, 0)
		for _, raspConfigRule := range raspConfig.Filter {
			for _, funName := range raspConfigRule.HookFunc {
				var probeConfigFilter ProbeConfigFilter
				var raspMethod RaspMethod

				cacheItem, err := raspMethodCache.Value(funName)
				if err != nil {
					err := raspMethodCol.FindOne(c, bson.M{"probe_hook": funName}).Decode(&raspMethod)
					if err != nil {
						continue
					}
					raspMethodCache.Add(funName, raspCacheTimeout, raspMethod)
				} else {
					raspMethod = cacheItem.Data().(RaspMethod)
				}
				probeConfigFilter.MethodId = raspMethod.MethodId
				probeConfigFilter.ClassId = raspMethod.ClassId
				probeConfigFilter.Exclude = make([]ProbeConfigRules, 0)
				probeConfigFilter.Include = make([]ProbeConfigRules, 0)

				if len(raspConfigRule.Rules) != 0 {
					for _, rule := range raspConfigRule.Rules {
						var probeConfigRules ProbeConfigRules
						probeConfigRules.Index = raspConfigRule.HookParam
						probeConfigRules.Regex = rule.Rule
						if rule.Type == "include" {
							probeConfigFilter.Include = append(probeConfigFilter.Include, probeConfigRules)
						} else if rule.Type == "exclude" {
							probeConfigFilter.Exclude = append(probeConfigFilter.Exclude, probeConfigRules)
						}
						hash += strconv.Itoa(probeConfigRules.Index) + probeConfigRules.Regex + rule.Type
					}
				}

				// 如果该方法已存在，合并rules
				if probeConfigRules, ok := funcMap[funName]; ok {
					for _, rules := range probeConfigFilter.Include {
						probeConfigRules.Include = append(probeConfigRules.Include, rules)
					}
					for _, rules := range probeConfigFilter.Exclude {
						probeConfigRules.Exclude = append(probeConfigRules.Exclude, rules)
					}
					funcMap[funName] = probeConfigRules
				} else {
					funcMap[funName] = probeConfigFilter
				}
				hash += strconv.Itoa(probeConfigFilter.MethodId) + strconv.Itoa(probeConfigFilter.ClassId)
			}
		}
		for _, probeConfigFilter := range funcMap {
			filterProbeConfig.Data.Filters = append(filterProbeConfig.Data.Filters, probeConfigFilter)
		}
		filterProbeConfig.Data.Uuid = md5Str(hash)
	}
	probeConfigList = append(probeConfigList, filterProbeConfig)

	var limitProbeConfig ProbeConfig
	limitProbeConfig.MessageType = RaspLimitType
	limitProbeConfig.Data.Limits = []ProbeConfigLimit{}
	probeConfigList = append(probeConfigList, limitProbeConfig)

	for _, runtime := range raspConfig.Runtime {
		if runtime == RaspRuntimeJava {
			var patchProbeConfig ProbeConfig
			patchProbeConfig.MessageType = RaspPatchType
			patchProbeConfig.Data.Patches = []ProbeConfigPatch{}
			probeConfigList = append(probeConfigList, patchProbeConfig)
		}
	}

	if !ifHasConfig {
		probeConfigList = make([]ProbeConfig, 0)
	}
	return
}

// 生成rasp任务
var agentTaskMap = make(map[string][]def.AgentTaskMsg)

func createRaspTask(raspConfig RaspTaskConfig, agentId string, pid string, runtime string) (err error) {

	taskLock.RLock()
	if pidList, ok := agentTaskMap[agentId]; ok {
		if len(pidList) >= 20 {
			taskLock.RUnlock()
			return
		}
	}

	taskLock.RUnlock()

	// 生成任务信息
	commands := make([]RaspPluginCommand, 0)
	raspPluginCommand := RaspPluginCommand{
		Pid:          pid,
		Runtime:      runtime,
		State:        RaspStateWaitAtt,
		ProbeMessage: raspConfig.TaskStr,
	}
	commands = append(commands, raspPluginCommand)

	raspTask := RaspPluginTask{
		Name:     "rasp",
		Commands: commands,
	}
	taskJson, err := json.Marshal(raspTask)
	if err != nil {
		return
	}
	agentQuickTask := def.AgentTaskMsg{
		Name:     "rasp",
		DataType: RaspTaskDataType,
		Data:     string(taskJson),
	}

	taskLock.Lock()
	if _, ok := agentTaskMap[agentId]; ok {
		agentTaskMap[agentId] = append(agentTaskMap[agentId], agentQuickTask)
	} else {
		agentTaskMap[agentId] = []def.AgentTaskMsg{agentQuickTask}
	}
	taskLock.Unlock()
	return
}

// rasp任务下发
func dealRaspTask(raspConfig RaspTaskConfig, raspInfo RaspHbType) (err error) {
	// 如果进程未被注入，直接注入
	if raspInfo.TraceState == RaspStateInspected {
		err = createRaspTask(raspConfig, raspInfo.AgentId, raspInfo.Pid, raspInfo.Runtime)
		return
	}

	// 如果已注入，存储，等待2996数据对比
	if raspInfo.TraceState == RaspStateAttached {
		key := "rasp-" + raspInfo.AgentId + "-" + raspInfo.Pid
		infra.Grds.SetNX(context.Background(), key, raspConfig.Id.String(), time.Minute*time.Duration(10))
		return
	}

	return
}

// rasp心跳数据格式化
func RaspHbFormat(raspData map[string]interface{}) (retRaspHbType RaspHbType, err error) {
	// 心跳数据格式化
	raspJson, err := json.Marshal(raspData)
	if err != nil {
		ylog.Errorf("[rasp]RaspHbFormat-Marshal", err.Error())
		return
	}
	err = json.Unmarshal(raspJson, &retRaspHbType)
	if err != nil {
		ylog.Errorf("[rasp]RaspHbFormat-Marshal", err.Error())
		return
	}

	for _, ip := range strings.Split(retRaspHbType.Ipv4Data, ",") {
		retRaspHbType.Ipv4List = append(retRaspHbType.Ipv4List, ip)
	}
	for _, ip := range strings.Split(retRaspHbType.Exv4Data, ",") {
		retRaspHbType.Exv4List = append(retRaspHbType.Exv4List, ip)
	}
	return
}

// rasp数据处理
// todo 打点
func dealRaspList(raspInfo RaspHbType) (err error) {
	// 筛选当前配置的语言项
	ifRuntime := false
	for _, runtimeC := range runtimeConfigList {
		if raspInfo.Runtime == runtimeC {
			ifRuntime = true
			break
		}
	}
	if !ifRuntime {
		return
	}

	if raspInfo.TraceState != RaspStateAttached && raspInfo.TraceState != RaspStateInspected {
		return
	}

	// 心跳数据过配置
	ifMatch, raspConfig, err := raspConfigMatch(raspInfo)
	if err != nil {
		ylog.Errorf("[rasp]dealRaspList-raspConfigMatch", err.Error())
		return
	}
	if !ifMatch {
		return
	}

	// 处理心跳任务
	err = dealRaspTask(raspConfig, raspInfo)
	if err != nil {
		return
	}

	return
}

// rasp 2996数据处理
func dealRaspConfigList(raspInfo RaspHbType) (err error) {

	// 过滤已注入进程，下发任务
	key := "rasp-" + raspInfo.AgentId + "-" + raspInfo.Pid
	configId, err := infra.Grds.Get(context.Background(), key).Result()
	if err != nil {
		return nil
	}
	infra.Grds.Del(context.Background(), key)

	configLock.Lock()
	raspConfig, ok := raspConfigIdMap[configId]
	configLock.Unlock()
	if ok {

		// 判断是否需要重新注入
		if raspInfo.Filter != raspConfig.FilterUuid ||
			raspInfo.Block != raspConfig.BlockUuid ||
			raspInfo.Limit != raspConfig.LimitUuid ||
			raspInfo.Patch != raspConfig.PatchUuid {
			err = createRaspTask(raspConfig, raspInfo.AgentId, raspInfo.Pid, raspInfo.Runtime)
		}
	}
	return
}

// rasp 2995插件状态数据处理
func dealRaspStatusList(raspInfo RaspHbType) (err error) {

	// 如果插件注入失败
	if raspInfo.Action == RaspStateAttFail {
		c := context.Background()
		raspCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintRaspCollection)
		_, err := raspCol.UpdateOne(c,
			bson.M{"agent_id": raspInfo.AgentId, "pid": raspInfo.Pid},
			bson.M{"$set": bson.M{"trace_state": RaspStateAttFail}})
		if err != nil {
			ylog.Errorf("Update error", err.Error())
		}
	}

	return
}

// rasp心跳数据处理
func RaspHbDeal(raspData RaspHbType) {
	switch raspData.DataType {
	case "2997":
		err := dealRaspList(raspData)
		if err != nil {
			ylog.Errorf("[rasp]RaspHbDeal: 2997", err.Error())
		}
	case "2996":
		err := dealRaspConfigList(raspData)
		if err != nil {
			ylog.Errorf("[rasp]RaspHbDeal: 2996", err.Error())
		}
	case "2995":
		err := dealRaspStatusList(raspData)
		if err != nil {
			ylog.Errorf("[rasp]RaspHbDeal: 2995", err.Error())
		}
	}
}

// rasp任务下发定时任务
func RaspTaskCronJob() {

	myFunc := func() {
		delAgentIdList := make([]string, 0)
		taskLock.RLock()
		for agentId, taskList := range agentTaskMap {

			redisKey := "rasp-task-" + agentId
			injectInfo, err := infra.Grds.Get(context.Background(), redisKey).Result()
			if err != nil {
				injectInfo = "0,0"
			}
			injectList := strings.Split(injectInfo, ",")
			if len(injectList) < 2 {
				infra.Grds.Del(context.Background(), redisKey)
				continue
			}
			injectNum, err := strconv.Atoi(injectList[0])
			if err != nil {
				infra.Grds.Del(context.Background(), redisKey)
				continue
			}
			injectTime, err := strconv.Atoi(injectList[1])
			if err != nil {
				infra.Grds.Del(context.Background(), redisKey)
				continue
			}

			if injectNum >= 20 && int(time.Now().Unix())-injectTime < 120 {
				continue
			} else {
				if injectTime > 120 {
					injectNum = len(taskList)
				} else {
					injectNum += len(taskList)
				}
				infra.Grds.Set(context.Background(), redisKey, strconv.Itoa(injectNum)+","+strconv.FormatInt(time.Now().Unix(), 10), -1)

				for _, task := range taskList {
					_, _ = atask.SendFastTask(agentId, &task, false, 300, nil)
				}
				delAgentIdList = append(delAgentIdList, agentId)
			}
		}
		taskLock.RUnlock()

		taskLock.Lock()
		for _, agentId := range delAgentIdList {
			delete(agentTaskMap, agentId)
		}
		taskLock.Unlock()
	}
	timer := time.NewTicker(time.Minute * time.Duration(1))
	for {
		select {
		case <-timer.C:
			myFunc()
		}
	}
}

func init() {
	raspMethodCache = cache2go.Cache("raspMethodCache")
}
