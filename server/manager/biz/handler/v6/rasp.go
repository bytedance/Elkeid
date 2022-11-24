package v6

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/rasp"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// 新增rasp配置
func NewRaspConfig(c *gin.Context) {
	var raspConfig rasp.RaspConfig

	// 绑定筛选数据
	err := c.BindJSON(&raspConfig)
	if err != nil {
		ylog.Errorf("NewRaspConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, "error")
		return
	}

	// 记录创建用户
	createUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	raspConfig.User = createUser.(string)
	raspConfig.Id = primitive.NewObjectID()
	if len(raspConfig.IpList) == 0 {
		raspConfig.IpList = make([]string, 0)
	}
	if len(raspConfig.EnvList) == 0 {
		raspConfig.EnvList = make([]string, 0)
	}
	if len(raspConfig.Runtime) == 0 {
		raspConfig.Runtime = make([]string, 0)
	}
	for i, runtime := range raspConfig.Runtime {
		if runtime == rasp.RaspRuntimeJava {
			raspConfig.Runtime[i] = "JVM"
		}
		if runtime == rasp.RaspRuntimePython {
			raspConfig.Runtime[i] = "CPython"
		}
	}

	raspConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspConfig)
	_, err = raspConfCol.InsertOne(c, raspConfig)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	time.Sleep(time.Duration(500) * time.Millisecond)
	common.CreateResponse(c, common.SuccessCode, nil)
}

// 删除rasp配置
func DelRaspConfig(c *gin.Context) {
	// 绑定组件信息
	var request struct {
		Id string `json:"id"`
	}

	// 绑定筛选数据
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("DelRaspConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, "error")
		return
	}
	id, _ := primitive.ObjectIDFromHex(request.Id)

	// 判断配置是否存在
	raspConfCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspConfig)
	count, err := raspConfCol.CountDocuments(c, bson.M{"_id": id})
	if count == 0 {
		common.CreateResponse(c, common.UnknownErrorCode, "can't find this config")
		return
	}

	// 删除组件
	_, err = raspConfCol.DeleteOne(c, bson.M{"_id": id})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	time.Sleep(time.Duration(500) * time.Millisecond)
	common.CreateResponse(c, common.SuccessCode, nil)
}

// 编辑rasp配置
func EditRaspConfig(c *gin.Context) {
	var raspConfig rasp.RaspConfig

	// 绑定筛选数据
	err := c.BindJSON(&raspConfig)
	if err != nil {
		ylog.Errorf("EditRaspConfig", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, "error")
		return
	}

	// 记录创建用户
	createUser, ok := c.Get("user")
	if !ok {
		common.CreateResponse(c, common.UnknownErrorCode, "user not login")
		return
	}
	raspConfig.User = createUser.(string)
	if len(raspConfig.IpList) == 0 {
		raspConfig.IpList = make([]string, 0)
	}
	if len(raspConfig.EnvList) == 0 {
		raspConfig.EnvList = make([]string, 0)
	}
	if len(raspConfig.Runtime) == 0 {
		raspConfig.Runtime = make([]string, 0)
	}
	for i, runtime := range raspConfig.Runtime {
		if runtime == rasp.RaspRuntimeJava {
			raspConfig.Runtime[i] = "JVM"
		}
		if runtime == rasp.RaspRuntimePython {
			raspConfig.Runtime[i] = "CPython"
		}
	}

	// 判断配置是否存在
	var oldConfig rasp.RaspConfig
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspConfig)
	err = collection.FindOne(c, bson.M{"_id": raspConfig.Id}).Decode(&oldConfig)
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, "can't find this config")
		return
	}

	// 更新组件
	_, err = collection.UpdateOne(c, bson.M{"_id": raspConfig.Id}, bson.M{"$set": raspConfig})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	time.Sleep(time.Duration(500) * time.Millisecond)

	common.CreateResponse(c, common.SuccessCode, nil)
}

// 查询rasp配置列表
func GetRaspConfigList(c *gin.Context) {
	var request struct {
		IfProtect []bool `json:"if_protect" bson:"if_protect"`
		Cmd       string `json:"cmd" bson:"cmd"`
		IfBlock   bool   `json:"if_block" bson:"if_block"`
		IfFilter  bool   `json:"if_filter" bson:"if_filter"`
		Env       string `json:"env" bson:"env"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetRaspConfigList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetRaspConfigList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	if len(request.IfProtect) != 0 {
		searchFilter["if_protect"] = common.MongoInside{Inside: request.IfProtect}
	}
	if request.Cmd != "" {
		searchFilter["cmd"] = common.MongoRegex{Regex: request.Cmd}
	}
	if request.IfFilter == true {
		searchFilter["filter.0"] = bson.M{"$exists": true}
	}
	if request.IfBlock == true {
		searchFilter["block.0"] = bson.M{"$exists": true}
	}
	if request.Env != "" {
		searchFilter["env_list"] = request.Env
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspConfig)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]rasp.RaspConfig, 0)
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var raspConfig rasp.RaspConfig
			err := cursor.Decode(&raspConfig)
			if err != nil {
				ylog.Errorf("GetRaspConfigList", err.Error())
				return err
			}

			for i, runtime := range raspConfig.Runtime {
				if runtime == "JVM" {
					raspConfig.Runtime[i] = rasp.RaspRuntimeJava
				}
				if runtime == "CPython" {
					raspConfig.Runtime[i] = rasp.RaspRuntimePython
				}
			}
			dataResponse = append(dataResponse, raspConfig)
			return nil
		},
	)
	if err != nil {
		ylog.Errorf("GetRaspConfigList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 查看rasp进程列表
func GetRaspProcessList(c *gin.Context) {
	var request struct {
		Cmdline  string   `json:"cmdline" bson:"cmdline"`
		Runtime  []string `json:"runtime" bson:"runtime"`
		Ip       string   `json:"ip" bson:"ip"`
		Status   []string `json:"status" bson:"trace_state"`
		Hostname string   `json:"hostname" bson:"hostname"`
		AgentId  string   `json:"agent_id" bson:"agent_id"`
		Env      string   `json:"env" bson:"env"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetRaspProcessList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	type Response struct {
		Id          string `json:"id" bson:"_id"`
		Cmdline     string `json:"cmdline" bson:"cmdline"`
		Hostname    string `json:"hostname" bson:"hostname"`
		Ip          string `json:"ip" bson:"ip"`
		Pid         string `json:"pid" bson:"pid"`
		Runtime     string `json:"runtime" bson:"runtime"`
		Status      string `json:"status" bson:"trace_state"`
		LastTime    int64  `json:"last_time" bson:"update_time"`
		ProtectTime int64  `json:"protect_time" bson:"attach_end_time"`
		AgentId     string `json:"agent_id" bson:"agent_id"`
	}
	// 绑定分页数据
	var pageRequest common.PageRequest
	err = c.BindQuery(&pageRequest)
	if err != nil {
		ylog.Errorf("GetRaspProcessList", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	// 拼接mongo查询语句
	searchFilter := make(map[string]interface{})
	lastDay := time.Now().Unix() - 86400
	searchFilter["update_time"] = common.MongoGte{Value: lastDay} // 超过一天的不显示
	if request.Cmdline != "" {
		searchFilter["cmdline"] = common.MongoRegex{Regex: request.Cmdline}
	}
	if len(request.Runtime) != 0 {
		searchFilter["runtime"] = common.MongoInside{Inside: request.Runtime}
	}
	if request.Ip != "" {
		searchFilter["$or"] = []bson.M{
			{"intranet_ipv4": request.Ip}, {"extranet_ipv4": request.Ip},
		}
	}
	if len(request.Status) != 0 {
		searchFilter["trace_state"] = common.MongoInside{Inside: request.Status}
	}
	if request.Hostname != "" {
		searchFilter["hostname"] = request.Hostname
	}
	if request.AgentId != "" {
		searchFilter["agent_id"] = request.AgentId
	}
	if request.Env != "" {
		if strings.Contains(request.Env, "=") {
			envSplit := strings.SplitN(request.Env, "=", 2)
			searchFilter["environ_json."+envSplit[0]] = envSplit[1]
		}
	}

	// 拼接分页数据
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintRaspCollection)
	pageSearch := common.PageSearch{Page: pageRequest.Page, PageSize: pageRequest.PageSize,
		Filter: searchFilter, Sorter: nil}
	if pageRequest.OrderKey != "" && (pageRequest.OrderValue == 1 || pageRequest.OrderValue == -1) {
		pageSearch.Sorter = bson.M{pageRequest.OrderKey: pageRequest.OrderValue}
	}

	// mongo查询并迭代处理
	dataResponse := make([]Response, 0)
	pageResponse, err := common.DBSearchPaginate(
		collection,
		pageSearch,
		func(cursor *mongo.Cursor) error {
			var raspProcess rasp.RaspProcess
			err := cursor.Decode(&raspProcess)
			if err != nil {
				ylog.Errorf("GetRaspProcessList", err.Error())
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return nil
			}
			response := Response{
				Cmdline:  raspProcess.Cmdline,
				Hostname: raspProcess.Hostname,
				Ip:       "",
				Pid:      raspProcess.Pid,
				Runtime:  raspProcess.Runtime,
				Status:   raspProcess.TraceState,
				AgentId:  raspProcess.AgentId,
			}
			response.LastTime = raspProcess.LastTime
			response.ProtectTime, _ = strconv.ParseInt(raspProcess.ProtectTime, 10, 64)

			if len(raspProcess.IntranetIpv4) > 0 {
				response.Ip = raspProcess.IntranetIpv4[0]
			}
			dataResponse = append(dataResponse, response)
			return nil
		},
	)

	if err != nil {
		ylog.Errorf("GetRaspProcessList", err.Error())
		CreatePageResponse(c, common.DBOperateErrorCode, dataResponse, *pageResponse)
		return
	}

	CreatePageResponse(c, common.SuccessCode, dataResponse, *pageResponse)
}

// 查询单个rasp详情
func GetRaspProcessDetail(c *gin.Context) {

	var request struct {
		AgentId string `json:"agent_id" bson:"agent_id"`
		Pid     string `json:"pid" bson:"pid"`
	}
	err := c.BindJSON(&request)
	if err != nil {
		ylog.Errorf("GetRaspProcessDetail", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	type Response struct {
		Cmdline        string `json:"cmdline" bson:"cmdline"`
		Hostname       string `json:"hostname" bson:"hostname"`
		Ip             string `json:"ip" bson:"ip"`
		Pid            string `json:"pid" bson:"pid"`
		Runtime        string `json:"runtime" bson:"runtime"`
		Status         string `json:"status" bson:"trace_state"`
		LastTime       int64  `json:"last_time" bson:"update_time"`
		ProtectTime    int64  `json:"protect_time" bson:"attach_end_time"`
		AgentId        string `json:"agent_id" bson:"agent_id"`
		ExeName        string `json:"exe_name" bson:"exe_name"`
		RuntimeVersion string `json:"runtime_version" bson:"runtime_version"`
		EnvironList    []struct {
			Key   string `json:"key" bson:"key"`
			Value string `json:"value" bson:"value"`
		} `json:"environ_list" bson:"environ_list"`
	}

	var raspProcess rasp.RaspProcess
	searchFilter := make(map[string]interface{})
	searchFilter["agent_id"] = request.AgentId
	searchFilter["pid"] = request.Pid
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintRaspCollection)
	err = collection.FindOne(c, searchFilter).Decode(&raspProcess)
	if err != nil {
		ylog.Errorf("GetRaspProcessDetail", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}

	if raspProcess.Runtime == "JVM" {
		raspProcess.Runtime = rasp.RaspRuntimeJava
	}
	if raspProcess.Runtime == "CPython" {
		raspProcess.Runtime = rasp.RaspRuntimePython
	}
	response := Response{
		Cmdline:        raspProcess.Cmdline,
		Hostname:       raspProcess.Hostname,
		Pid:            raspProcess.Pid,
		Runtime:        raspProcess.Runtime,
		Status:         raspProcess.TraceState,
		AgentId:        raspProcess.AgentId,
		RuntimeVersion: raspProcess.RuntimeVersion,
		ExeName:        raspProcess.ExeName,
	}
	response.LastTime = raspProcess.LastTime
	response.ProtectTime, _ = strconv.ParseInt(raspProcess.ProtectTime, 10, 64)
	if len(raspProcess.IntranetIpv4) > 0 {
		response.Ip = raspProcess.IntranetIpv4[0]
	}

	// 环境变量排序
	keys := make([]string, 0)
	for k := range raspProcess.EnvironJson {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type tmpStruct struct {
		Key   string `json:"key" bson:"key"`
		Value string `json:"value" bson:"value"`
	}
	for _, i := range keys {
		tmp := tmpStruct{
			Key:   i,
			Value: raspProcess.EnvironJson[i],
		}
		response.EnvironList = append(response.EnvironList, tmp)
	}

	common.CreateResponse(c, common.SuccessCode, response)
}

// 获取rasp统计数据
func GetRaspStatistics(c *gin.Context) {
	var response struct {
		InspectState struct {
			Inspected   int64 `json:"inspected" bson:"inspected"`
			Attached    int64 `json:"attached" bson:"attached"`
			WaitAttache int64 `json:"wait_attache" bson:"wait_attache"`
			Closing     int64 `json:"closing" bson:"closing"`
			WaitInspect int64 `json:"wait_inspect" bson:"wait_inspect"`
		} `json:"inspect_state" bson:"inspect_state"`
		Runtime struct {
			Python int64 `json:"python" bson:"CPython"`
			Java   int64 `json:"java" bson:"JVM"`
			NodeJS int64 `json:"nodejs" bson:"NodeJS"`
			Golang int64 `json:"golang" bson:"Golang"`
			Php    int64 `json:"php" bson:"PHP"`
		} `json:"runtime" bson:"runtime"`
		ProcessNum int64 `json:"process_num" bson:"process_num"`
	}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintRaspCollection)

	// 获取状态统计信息
	lastDayUnix := time.Now().Unix() - 86400
	cursor, err := collection.Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{"update_time": bson.M{"$gte": lastDayUnix}},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$trace_state",
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
	})
	if err != nil {
		ylog.Errorf("GetRaspStatistics", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	for cursor.Next(c) {
		level, ok1 := cursor.Current.Lookup("_id").StringValueOK()
		count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
		if ok1 && ok2 {
			response.ProcessNum += count
			switch level {
			case rasp.RaspStateInspected:
				response.InspectState.Inspected = count
			case rasp.RaspStateAttached:
				response.InspectState.Attached = count
			case rasp.RaspStateClose:
				response.InspectState.Closing = count
			case rasp.RaspStateWaitAtt:
				response.InspectState.WaitAttache = count
			case rasp.RaspStateWaitIns:
				response.InspectState.WaitInspect = count
			}
		}
	}

	// 获取运行时统计信息
	cursor, err = collection.Aggregate(c, bson.A{
		bson.M{
			"$match": bson.M{"update_time": bson.M{"$gte": lastDayUnix}},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$runtime",
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
	})
	if err != nil {
		ylog.Errorf("GetRaspStatistics", err.Error())
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	for cursor.Next(c) {
		runtime, ok1 := cursor.Current.Lookup("_id").StringValueOK()
		count, ok2 := cursor.Current.Lookup("count").AsInt64OK()
		if ok1 && ok2 {
			switch runtime {
			case rasp.HeartBeartPython:
				response.Runtime.Python = count
			case rasp.HeartBeartGolang:
				response.Runtime.Golang = count
			case rasp.HeartBeartJava:
				response.Runtime.Java = count
			case rasp.HeartBeartNodeJS:
				response.Runtime.NodeJS = count
			case rasp.HeartBeartPhp:
				response.Runtime.Php = count
			}
		}
	}
	common.CreateResponse(c, common.SuccessCode, response)
}

// 获取rasp函数列表
func GetRaspMethodMap(c *gin.Context) {
	var response struct {
		Python []string `json:"Python" bson:"Python"`
		Java   []string `json:"Java" bson:"Java"`
		Golang []string `json:"Golang" bson:"Golang"`
		Php    []string `json:"PHP" bson:"PHP"`
		Nodejs []string `json:"NodeJS" bson:"NodeJS"`
	}

	raspMethodCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.RaspMethod)

	cur, err := raspMethodCol.Find(c, bson.M{})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	response.Python = make([]string, 0)
	response.Java = make([]string, 0)
	response.Golang = make([]string, 0)
	response.Php = make([]string, 0)
	response.Nodejs = make([]string, 0)

	for cur.Next(c) {
		var raspMethod rasp.RaspMethod
		err := cur.Decode(&raspMethod)
		if err != nil {
			continue
		}
		switch raspMethod.Runtime {
		case rasp.RaspRuntimePython:
			response.Python = append(response.Python, raspMethod.ProbeHook)
		case rasp.RaspRuntimePhp:
			response.Php = append(response.Php, raspMethod.ProbeHook)
		case rasp.RaspRuntimeJava:
			response.Java = append(response.Java, raspMethod.ProbeHook)
		case rasp.RaspRuntimeGolang:
			response.Golang = append(response.Golang, raspMethod.ProbeHook)
		case rasp.RaspRuntimeNodeJS:
			response.Nodejs = append(response.Nodejs, raspMethod.ProbeHook)
		}
	}

	common.CreateResponse(c, common.SuccessCode, response)
}

// 下发热补丁任务
