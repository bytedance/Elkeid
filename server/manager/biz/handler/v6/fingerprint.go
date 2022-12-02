package v6

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"strconv"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/internal/asset_center"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/utils"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/cronjob"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	cooldownSeconds = 30 * 60
	timeoutSeconds  = 15 * 60
)

var FPType = map[string]int32{"port": 5051, "process": 5050, "user": 5052, "cron": 5053, "service": 5054, "software": 5055, "container": 5056, "integrity": 5057, "app": 5060, "kmod": 5062}

type FPTaskItem struct {
	DataType   int32  `json:"data_type" bson:"data_type"`
	TaskID     string `json:"task_id" bson:"task_id"`
	UpdateTime int64  `json:"update_time" bson:"update_time"`
}
type RefreshDataReqBody struct {
	FingerprintType string `json:"fingerprint_type" binding:"required"`
	AgentID         string `json:"agent_id"`
}

func RefreshData(c *gin.Context) {
	rb := &RefreshDataReqBody{}
	err := c.Bind(rb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	dataType, ok := FPType[rb.FingerprintType]
	if !ok {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "fingerprint_type not support")
		return
	}

	filter := bson.M{"data_type": dataType}
	LockKey := fmt.Sprintf("FingerPrint-RefreshData-%d", dataType)
	if rb.AgentID != "" {
		LockKey += rb.AgentID
		filter["agent_id"] = rb.AgentID
		cl := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		if s := cl.FindOne(c, bson.M{"agent_id": rb.AgentID}); s.Err() != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, s.Err().Error())
			return
		}
	} else {
		filter["agent_id"] = bson.M{"$exists": false}
	}
	ok, err = infra.DistributedLockWithExpireTime(LockKey, cooldownSeconds*time.Second)
	if err != nil {
		common.CreateResponse(c, common.RedisOperateErrorCode, err.Error())
		return
	}
	if !ok {
		common.CreateResponse(c, common.ExceedLimitErrorCode, "Exceed the frequency limit")
		return
	}

	defer func() {
		err = infra.DistributedUnLock(LockKey)
		if err != nil {
			ylog.Errorf("RefreshData", "DistributedUnLock %s error %s", LockKey, err.Error())
		}
	}()

	fpItem := FPTaskItem{}
	fpCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerPrintRefreshTaskCollection)
	err = fpCollection.FindOne(c, filter).Decode(&fpItem)
	if err != nil && err != mongo.ErrNoDocuments {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	if time.Now().Unix()-fpItem.UpdateTime < cooldownSeconds {
		common.CreateResponse(c, common.ExceedLimitErrorCode, "Exceed the frequency limit")
		return
	}

	var taskID string
	if rb.AgentID != "" {
		taskLinux := &def.AgentTaskMsg{
			Name:     "collector",
			Data:     "",
			DataType: dataType,
		}
		taskID, err = atask.SendFastTask(rb.AgentID, taskLinux, true, timeoutSeconds, nil)
		if err != nil {
			common.CreateResponse(c, common.UnknownErrorCode, err.Error())
			return
		}
	} else {
		taskParam := atask.AgentTask{
			Filter: &common.FilterQuery{Condition: "$and", Filter: []common.FilterContent{
				{
					Key:       "last_heartbeat_time",
					Rules:     []common.FilterRule{{Operator: "$gte", Value: time.Now().Unix() - asset_center.DEFAULT_OFFLINE_DURATION}},
					Condition: "$and",
				}}},
			TaskName: "collector",
			Data: def.ConfigRequest{
				Task: def.AgentTaskMsg{
					Name:     "collector",
					Data:     "",
					DataType: dataType,
				},
			},
			SubTaskRunningTimeout: timeoutSeconds,
		}
		taskID, _, err = atask.CreateTaskAndRun(&taskParam, atask.TypeAgentTask, 5)
		if err != nil {
			common.CreateResponse(c, common.UnknownErrorCode, err.Error())
			return
		}
	}

	fpItem = FPTaskItem{
		DataType:   dataType,
		TaskID:     taskID,
		UpdateTime: time.Now().Unix(),
	}
	_, err = fpCollection.UpdateOne(c, filter, bson.M{"$set": fpItem}, (&options.UpdateOptions{}).SetUpsert(true))
	if err != nil {
		common.CreateResponse(c, common.UnknownErrorCode, err.Error())
		return
	}

	common.CreateResponse(c, common.SuccessCode, taskID)
}

type FPStatus struct {
	Status       string `json:"status"`
	Percent      int64  `json:"percent"`
	UpdateTime   int64  `json:"update_time"`
	CooldownTime int64  `json:"cooldown_time"`
}

func DescribeRefreshStatus(c *gin.Context) {
	filter := bson.M{}
	idExists := true
	if id, ok := c.GetQuery("agent_id"); ok {
		filter["agent_id"] = id
		cl := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		if s := cl.FindOne(c, filter); s.Err() != nil {
			common.CreateResponse(c, common.ParamInvalidErrorCode, s.Err().Error())
			return
		}
	} else {
		idExists = false
		filter["agent_id"] = bson.M{"$exists": false}
	}
	fingerprintType := c.Query("fingerprint_type")
	dataType, ok := FPType[fingerprintType]
	if !ok {
		common.CreateResponse(c, common.ParamInvalidErrorCode, "fingerprint_type not support")
		return
	}
	filter["data_type"] = dataType
	fpItem := FPTaskItem{}
	fpCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerPrintRefreshTaskCollection)
	err := fpCollection.FindOne(c, filter).Decode(&fpItem)
	// no history
	if errors.Is(err, mongo.ErrNoDocuments) {
		common.CreateResponse(c, common.SuccessCode, FPStatus{
			Status:     "success",
			Percent:    0,
			UpdateTime: 0,
		})
		return
	}
	// else error
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}

	//query task status
	fps := FPStatus{
		Status:     "success",
		Percent:    0,
		UpdateTime: 0,
	}
	if idExists {
		//query subtask status
		taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
		at := atask.AgentSubTask{}
		err = taskCollection.FindOne(c, bson.M{"task_id": fpItem.TaskID}).Decode(&at)
		if errors.Is(err, mongo.ErrNoDocuments) {
			common.CreateResponse(c, common.SuccessCode, fps)
			return
		}
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		now := time.Now().Unix()
		fps.UpdateTime = at.UpdateTime
		//运行结束
		if at.Status == atask.TaskStatusResultSuccess || at.Status == atask.TaskStatusResultFail {
			fps.Percent = 100
			if now-at.UpdateTime < cooldownSeconds {
				fps.Status = "cooling"
				fps.CooldownTime = cooldownSeconds - (now - at.UpdateTime)
			}
		}
	} else {
		taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
		at := atask.AgentTask{}
		err = taskCollection.FindOne(c, bson.M{"task_id": fpItem.TaskID}).Decode(&at)
		if errors.Is(err, mongo.ErrNoDocuments) {
			common.CreateResponse(c, common.SuccessCode, fps)
			return
		}
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}

		percent := int64((at.SubTaskSucceed + at.SubTaskFailed) * 100 / int(at.IDCount))
		if percent > 100 {
			percent = 100
		}
		fps.Percent = percent
		fps.UpdateTime = at.UpdateTime

		//运行结束
		now := time.Now().Unix()
		if at.TaskStatus == atask.TaskStatusFinished && now-at.UpdateTime < cooldownSeconds {
			fps.Status = "cooling"
			fps.CooldownTime = cooldownSeconds - (now - at.UpdateTime)
		}
	}

	common.CreateResponse(c, common.SuccessCode, fps)
}

type BasicHostQuery struct {
	AgentID  string `json:"agent_id"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

func (q *BasicHostQuery) MarshalToBson(m bson.M) {
	if q.AgentID != "" {
		m["agent_id"] = q.AgentID
	}
	if q.IP != "" {
		m["$or"] = bson.A{
			bson.M{"intranet_ipv4": q.IP},
			bson.M{"extranet_ipv4": q.IP},
			bson.M{"intranet_ipv6": q.IP},
			bson.M{"extranet_ipv6": q.IP},
		}
	}
	if q.Hostname != "" {
		m["hostname"] = q.Hostname
	}
}

type BasicHostInfo struct {
	AgentID      string   `json:"agent_id" bson:"agent_id"`
	IntranetIpv4 []string `json:"intranet_ipv4" bson:"intranet_ipv4"`
	IntranetIpv6 []string `json:"intranet_ipv6" bson:"intranet_ipv6"`
	ExtranetIpv4 []string `json:"extranet_ipv4" bson:"extranet_ipv4"`
	ExtranetIpv6 []string `json:"extranet_ipv6" bson:"extranet_ipv6"`
	Hostname     string   `json:"hostname" bson:"hostname"`
}
type BasicFingerprintInfo struct {
	Id         string `json:"_id" bson:"_id"`
	UpdateTime int64  `json:"update_time" bson:"update_time"`
}

// DescribeProcess defs
type DescribeProcessReqBody struct {
	BasicHostQuery
	Comm           string `json:"comm"`
	Cmdline        string `json:"cmdline"`
	Exe            string `json:"exe"`
	Checksum       string `json:"checksum"`
	Username       string `json:"username"`
	Integrity      *bool  `json:"integrity"`
	Common         *bool  `json:"common"`
	Container      *bool  `json:"container"`
	StartTimeStart *int   `json:"start_time_start"`
	StartTimeEnd   *int   `json:"start_time_end"`
}

func (q *DescribeProcessReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.Comm != "" {
		m["comm"] = utils.TransBackwardsRegex(q.Comm)
	}
	if q.Cmdline != "" {
		m["cmdline"] = utils.TransBackwardsRegex(q.Cmdline)
	}
	if q.Exe != "" {
		m["exe"] = utils.TransBackwardsRegex(q.Exe)
	}
	if q.Checksum != "" {
		m["checksum"] = q.Checksum
	}
	if q.Username != "" {
		m["rusername"] = utils.TransBackwardsRegex(q.Username)
	}
	if q.Integrity != nil {
		if *q.Integrity {
			m["integrity"] = "true"
		} else {
			m["integrity"] = "false"
		}
	}
	if q.Common != nil {
		m["common"] = *q.Common
	}
	if q.Container != nil {
		if *q.Container {
			m["container_id"] = bson.M{"$ne": ""}
		} else {
			m["container_id"] = ""
		}
	}
	if q.StartTimeStart != nil && q.StartTimeEnd != nil {
		m["start_time"] = bson.M{
			"$gte": *q.StartTimeStart,
			"$lt":  *q.StartTimeEnd,
		}
	}
}

type DescribeProcessRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Pid                  string `json:"pid" bson:"pid"`
	Ppid                 string `json:"ppid" bson:"ppid"`
	Comm                 string `json:"comm" bson:"comm"`
	Cmdline              string `json:"cmdline" bson:"cmdline"`
	Exe                  string `json:"exe" bson:"exe"`
	Checksum             string `json:"checksum" bson:"checksum"`
	Uid                  string `json:"uid" bson:"ruid"`
	Username             string `json:"username" bson:"rusername"`
	Euid                 string `json:"euid" bson:"euid"`
	Euername             string `json:"eusername" bson:"eusername"`
	StartTime            int    `json:"start_time" bson:"start_time"`
	ContainerID          string `json:"container_id" bson:"container_id"`
	ContainerName        string `json:"container_name" bson:"container_name"`
	Integrity            bool   `json:"integrity" bson:"-"`
	Common               bool   `json:"common" bson:"common"`
	State                string `json:"state" bson:"state"`
}

func DescribeProcess(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeProcessReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintProcessCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeProcessRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeProcessRespItem{}
		err = c.Decode(&p)
		if err == nil {
			if integrity, ok := c.Current.Lookup("integrity").StringValueOK(); ok {
				p.Integrity = integrity == "true"
			}
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

// DescribePort defs
type DescribePortReqBody struct {
	BasicHostQuery
	Sip      string `json:"sip" bson:"sip,omitempty"`
	Sport    string `json:"sport" bson:"sport,omitempty"`
	Username string `json:"username" bson:"username,omitempty"`
	Exe      string `json:"exe" bson:"exe,omitempty"`
	Cmdline  string `json:"cmdline" bson:"cmdline,omitempty"`
	Comm     string `json:"comm" bson:"comm,omitempty"`
	Type     []int  `json:"type" binding:"omitempty,dive,oneof=6 17" bson:"type,omitempty"`
}

func (q *DescribePortReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.Sip != "" {
		m["sip"] = utils.TransBackwardsRegex(q.Sip)
	}
	if q.Sport != "" {
		m["sport"] = q.Sport
	}
	if q.Username != "" {
		m["username"] = utils.TransBackwardsRegex(q.Username)
	}
	if q.Exe != "" {
		m["exe"] = utils.TransBackwardsRegex(q.Exe)
	}
	if q.Cmdline != "" {
		m["cmdline"] = utils.TransBackwardsRegex(q.Cmdline)
	}
	if q.Comm != "" {
		m["comm"] = utils.TransBackwardsRegex(q.Comm)
	}
	if len(q.Type) != 0 {
		var types []string
		for _, t := range q.Type {
			types = append(types, strconv.Itoa(t))
		}
		m["protocol"] = bson.M{"$in": types}
	}
}

type DescribePortRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Sip                  string `json:"sip" bson:"sip"`
	Sport                string `json:"sport" bson:"sport"`
	Dip                  string `json:"dip" bson:"dip"`
	Dport                string `json:"dport" bson:"dport"`
	Interface            string `json:"interface" bson:"interface"`
	Family               string `json:"family" bson:"family"`
	State                string `json:"state" bson:"state"`
	Uid                  string `json:"uid" bson:"uid"`
	Username             string `json:"username" bson:"username"`
	Inode                string `json:"inode" bson:"inode"`
	Pid                  string `json:"pid" bson:"pid"`
	Exe                  string `json:"exe" bson:"exe"`
	Cmdline              string `json:"cmdline" bson:"cmdline"`
	Comm                 string `json:"comm" bson:"comm"`
	Type                 int    `json:"type" bson:"-"`
	ContainerID          string `json:"container_id" bson:"container_id"`
	ContainerName        string `json:"container_name" bson:"container_name"`
}

func DescribePort(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribePortReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintPortCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribePortRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribePortRespItem{}
		err = c.Decode(&p)
		if err == nil {
			if t, ok := c.Current.Lookup("protocol").StringValueOK(); ok {
				p.Type, _ = strconv.Atoi(t)
			}
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

// DescribeUser defs
type DescribeUserReqBody struct {
	BasicHostQuery     `bson:"inline"`
	LastLoginIP        string `json:"last_login_ip"`
	Username           string `json:"username"`
	GroupName          string `json:"group_name"`
	LastLoginTimeStart *int64 `json:"last_login_time_start"`
	LastLoginTimeEnd   *int64 `json:"last_login_time_end"`
}

func (q *DescribeUserReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.LastLoginIP != "" {
		m["last_login_ip"] = q.LastLoginIP
	}
	if q.Username != "" {
		m["username"] = utils.TransBackwardsRegex(q.Username)
	}
	if q.GroupName != "" {
		m["groupname"] = utils.TransBackwardsRegex(q.GroupName)
	}
	if q.LastLoginTimeStart != nil && q.LastLoginTimeEnd != nil {
		m["last_login_time"] = bson.M{
			"$gte": *q.LastLoginTimeStart,
			"$lte": *q.LastLoginTimeEnd,
		}
	}
}

type DescribeUserRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	LastLoginIP          string `json:"last_login_ip" bson:"last_login_ip"`
	LastLoginTime        int    `json:"last_login_time" bson:"last_login_time"`
	Username             string `json:"username" bson:"username"`
	Password             string `json:"password" bson:"password"`
	Uid                  string `json:"uid" bson:"uid"`
	Gid                  string `json:"gid" bson:"gid"`
	Info                 string `json:"info" bson:"info"`
	HomeDir              string `json:"home_dir" bson:"home"`
	GroupName            string `json:"group_name" bson:"groupname"`
	Shell                string `json:"shell" bson:"shell"`
	Sudoers              string `json:"sudoers" bson:"sudoers"`
}

func DescribeUser(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeUserReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintUserCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeUserRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeUserRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

// DescribeCron defs
type DescribeCronReqBody struct {
	BasicHostQuery `bson:"inline"`
	Path           string `json:"path" bson:"path"`
	Username       string `json:"username" bson:"username"`
	Command        string `json:"command" bson:"command"`
	Checksum       string `json:"checksum" bson:"checksum"`
}

func (q *DescribeCronReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.Path != "" {
		m["path"] = utils.TransBackwardsRegex(q.Path)
	}
	if q.Username != "" {
		m["username"] = utils.TransBackwardsRegex(q.Username)
	}
	if q.Command != "" {
		m["command"] = utils.TransBackwardsRegex(q.Command)
	}
	if q.Checksum != "" {
		m["checksum"] = q.Checksum
	}
}

type DescribeCronRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Path                 string `json:"path" bson:"path"`
	Username             string `json:"username" bson:"username"`
	Command              string `json:"command" bson:"command"`
	Checksum             string `json:"checksum" bson:"checksum"`
	Schedule             string `json:"schedule" bson:"schedule"`
}

func DescribeCron(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeCronReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintCrontabCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeCronRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeCronRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

// DescribeService defs
type DescribeServiceReqBody struct {
	BasicHostQuery `bson:"inline"`
	Path           string   `json:"path" bson:"path"`
	Name           string   `json:"name"`
	Type           []string `json:"type" binding:"omitempty,dive,oneof=simple exec forking oneshot dbus notify idle"`
	Command        string   `json:"command"`
	Restart        string   `json:"restart" binding:"omitempty,oneof=false true"`
	Checksum       string   `json:"checksum"`
}

func (q *DescribeServiceReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.Path != "" {
		m["path"] = utils.TransBackwardsRegex(q.Path)
	}
	if q.Name != "" {
		m["name"] = utils.TransBackwardsRegex(q.Name)
	}
	if len(q.Type) != 0 {
		m["type"] = bson.M{"$in": q.Type}
	}
	if q.Restart != "" {
		m["restart"] = q.Restart
	}
	if q.Command != "" {
		m["command"] = utils.TransBackwardsRegex(q.Command)
	}
	if q.Checksum != "" {
		m["checksum"] = q.Checksum
	}
}

type DescribeServiceRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"name"`
	Type                 string `json:"type" bson:"type"`
	Command              string `json:"command" bson:"command"`
	Restart              string `json:"restart" bson:"restart"`
	WorkingDirectory     string `json:"working_directory" bson:"working_dir"`
	Checksum             string `json:"checksum" bson:"checksum"`
}

func DescribeService(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeServiceReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintServiceCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeServiceRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeServiceRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

// DescribeSoftwaredefs
type DescribeSoftwareReqBody struct {
	BasicHostQuery `bson:"inline"`
	Name           string   `json:"name" bson:"name"`
	Type           []string `json:"type" bson:"type" binding:"omitempty,dive,oneof=dpkg rpm pypi jar"`
	Version        string   `json:"version" bson:"sversion"`
}

func (q *DescribeSoftwareReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.Name != "" {
		m["name"] = utils.TransBackwardsRegex(q.Name)
	}
	if len(q.Type) != 0 {
		m["type"] = bson.M{"$in": q.Type}
	}
	if q.Version != "" {
		m["sversion"] = utils.TransBackwardsRegex(q.Version)
	}
}

type DescribeSoftwareRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"name"`
	Type                 string `json:"type" bson:"type"`
	Version              string `json:"version" bson:"sversion"`
}

func DescribeSoftware(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeSoftwareReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintSoftwareCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeSoftwareRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeSoftwareRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type ExportDataReqBody struct {
	FingerprintType string          `json:"fingerprint_type" binding:"oneof=process port user cron service software container integrity app kmod"`
	IdList          []string        `json:"id_list" binding:"required_without=Conditions"`
	Conditions      json.RawMessage `json:"conditions" binding:"required_without=IdList"`
}

func ExportData(c *gin.Context) {
	rb := &ExportDataReqBody{}
	err := c.BindJSON(rb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	m := bson.M{}
	var (
		collection string
		defs       = common.MongoDBDefs{
			{"agent_id", "AgentID"},
			{"hostname", "Hostname"},
			{"intranet_ipv4", "IntranetIPv4"},
			{"extranet_ipv4", "ExtranetIPv4"},
			{"intranet_ipv6", "IntranetIPv6"},
			{"extranet_ipv6", "ExtranetIPv6"},
		}
	)
	if len(rb.IdList) != 0 {
		il := bson.A{}
		for _, id := range rb.IdList {
			if oid, err := primitive.ObjectIDFromHex(id); err == nil {
				il = append(il, oid)
			}
		}
		m["_id"] = bson.M{"$in": il}
	}
	switch rb.FingerprintType {
	case "process":
		if len(rb.IdList) == 0 {
			cond := &DescribeProcessReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintProcessCollection
		defs = append(defs, common.MongoDBDefs{
			{"pid", "Pid"},
			{"comm", "Comm"},
			{"cmdline", "Cmdline"},
			{"exe", "Exe"},
			{"ruid", "Uid"},
			{"rusername", "Username"},
			{"ppid", "Ppid"},
			{"checksum", "Checksum"},
			{"start_time", "StartTime"},
		}...)
	case "port":
		if len(rb.IdList) == 0 {
			cond := &DescribePortReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintPortCollection
		defs = append(defs, common.MongoDBDefs{
			{"sip", "Sip"},
			{"sport", "Sport"},
			{"protocol", "Type"},
			{"pid", "Pid"},
			{"comm", "Comm"},
			{"cmdline", "Cmdline"},
			{"uid", "Uid"},
			{"username", "Username"},
		}...)
	case "user":
		if len(rb.IdList) == 0 {
			cond := &DescribeUserReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintUserCollection
		defs = append(defs, common.MongoDBDefs{
			{"uid", "Uid"},
			{"username", "Username"},
			{"gid", "Gid"},
			{"groupname", "GroupName"},
			{"last_login_time", "LastLoginTime"},
			{"last_login_ip", "LastLoginIP"},
			{"home", "HomeDir"},
			{"shell", "Shell"},
			{"info", "Info"},
		}...)
	case "cron":
		if len(rb.IdList) == 0 {
			cond := &DescribeCronReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintCrontabCollection
		defs = append(defs, common.MongoDBDefs{
			{"command", "Command"},
			{"path", "Path"},
			{"checksum", "Checksum"},
			{"schedule", "Schedule"},
			{"username", "Username"},
		}...)
	case "service":
		if len(rb.IdList) == 0 {
			cond := &DescribeServiceReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintServiceCollection
		defs = append(defs, common.MongoDBDefs{
			{"name", "Name"},
			{"type", "Type"},
			{"command", "Command"},
			{"working_dir", "WorkingDir"},
			{"username", "Username"},
			{"checksum", "Checksum"},
			{"restart", "Restart"},
		}...)
	case "software":
		if len(rb.IdList) == 0 {
			cond := &DescribeSoftwareReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintSoftwareCollection
		defs = append(defs, common.MongoDBDefs{
			{"name", "Name"},
			{"type", "Type"},
			{"sversion", "Version"},
		}...)
	case "container":
		if len(rb.IdList) == 0 {
			cond := &DescribeContainerReq{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintContainerCollection
		defs = append(defs, common.MongoDBDefs{
			{"id", "ID"},
			{"name", "Name"},
			{"image_id", "ImageId"},
			{"image_name", "ImageName"},
			{"state", "State"},
			{"create_time", "CreateTime"},
		}...)
	case "integrity":
		if len(rb.IdList) == 0 {
			cond := &DescribeIntegrityReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintIntegrityCollection
		defs = append(defs, common.MongoDBDefs{
			{"software_name", "Name"},
			{"software_version", "Version"},
			{"exe", "Exe"},
			{"origin_digest", "OriginDigest"},
			{"digest", "Digest"},
			{"modify_time", "ModifyTime"},
		}...)
	case "app":
		if len(rb.IdList) == 0 {
			cond := &DescribeAppReq{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintAppCollection
		defs = append(defs, common.MongoDBDefs{
			{"name", "Name"},
			{"type", "Type"},
			{"sversion", "Version"},
			{"container_id", "ContainerID"},
			{"container_name", "ContainerName"},
			{"pid", "Pid"},
			{"exe", "Exe"},
			{"start_time", "StartTime"},
		}...)
	case "kmod":
		if len(rb.IdList) == 0 {
			cond := &DescribeIntegrityReqBody{}
			err = json.Unmarshal(rb.Conditions, cond)
			if err != nil {
				common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
				return
			}
			cond.MarshalToBson(m)
		}
		collection = infra.FingerprintIntegrityCollection
		defs = append(defs, common.MongoDBDefs{
			{"name", "Name"},
			{"size", "Size"},
			{"refcount", "Refcount"},
			{"used_by", "UsedBy"},
			{"state", "State"},
			{"addr", "Addr"},
		}...)
	}
	defs = append(defs, struct {
		Key    string
		Header string
	}{"update_time", "UpdateTime"})
	common.ExportFromMongoDB(
		c,
		infra.MongoClient.Database(infra.MongoDatabase).Collection(collection),
		m,
		defs,
		rb.FingerprintType,
	)
}

type DescribeStatisticsResp struct {
	Port      int64 `json:"port"`
	Process   int64 `json:"process"`
	User      int64 `json:"user"`
	Cron      int64 `json:"cron"`
	Service   int64 `json:"service"`
	Software  int64 `json:"software"`
	Container int64 `json:"container"`
	Integrity int64 `json:"integrity"`
	Kmod      int64 `json:"kmod"`
	App       int64 `json:"app"`
}

func DescribeStatistics(c *gin.Context) {
	filter := bson.M{}
	if id, ok := c.GetQuery("agent_id"); ok {
		filter["agent_id"] = id
	}
	if len(filter) > 0 {
		var err error
		resp := DescribeStatisticsResp{}
		cls := []string{infra.FingerprintPortCollection,
			infra.FingerprintProcessCollection,
			infra.FingerprintUserCollection,
			infra.FingerprintCrontabCollection,
			infra.FingerprintServiceCollection,
			infra.FingerprintSoftwareCollection,
			infra.FingerprintContainerCollection,
			infra.FingerprintIntegrityCollection,
			infra.FingerprintKmodCollection,
			infra.FingerprintAppCollection}
		wg := sync.WaitGroup{}
		wg.Add(len(cls))
		for i, n := range cls {
			go func(i int, n string) {
				defer wg.Done()
				collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(n)
				var v int64
				if len(filter) == 0 {
					v, err = collection.EstimatedDocumentCount(c)
				} else {
					v, err = collection.CountDocuments(c, filter)
				}
				switch i {
				case 0:
					resp.Port = v
				case 1:
					resp.Process = v
				case 2:
					resp.User = v
				case 3:
					resp.Cron = v
				case 4:
					resp.Service = v
				case 5:
					resp.Software = v
				case 6:
					resp.Container = v
				case 7:
					resp.Integrity = v
				case 8:
					resp.Kmod = v
				case 9:
					resp.App = v
				}
			}(i, n)
		}
		wg.Wait()
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		} else {
			common.CreateResponse(c, common.SuccessCode, resp)
		}
	} else {
		m, err := cronjob.GetLatestResult(c.FullPath())
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		} else {
			common.CreateResponse(c, common.SuccessCode, m)
		}
	}
}

func DescribeTop5(c *gin.Context) {
	t := c.Query("fingerprint_type")
	switch t {
	case "process", "port", "service", "software", "app", "kmod":
		res, err := cronjob.GetLatestResult("/api/v6/fingerprint/DescribeTop5")
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
			return
		}
		if items, ok := res[t]; ok {
			common.CreateResponse(c, common.SuccessCode, items)
		} else {
			common.CreateResponse(c, common.SuccessCode, []interface{}{})
		}
	case "integrity":
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.LookupCollection(t))
		cursor, err := collection.Find(c, bson.M{}, options.Find().SetSort(bson.M{"modify_time": -1}).SetLimit(5))
		if err != nil {
			common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		} else {
			var items []map[string]interface{}
			for cursor.Next(c) {
				i := DescribeIntegrityRespItem{}
				err = cursor.Decode(&i)
				if err != nil {
					common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
					break
				}
				items = append(items, map[string]interface{}{"name": i.Exe, "value": i.ModifyTime})
			}
			common.CreateResponse(c, common.SuccessCode, items)
		}

	default:
		common.CreateResponse(c, common.ParamInvalidErrorCode, "fingerprint_type is invalid")
	}
}

type DescribeIntegrityReqBody struct {
	BasicHostQuery
	Name            string `json:"name"`
	Version         string `json:"version"`
	OriginDigest    string `json:"origin_digest"`
	Digest          string `json:"digest"`
	Exe             string `json:"exe"`
	ModifyTimeStart *int   `json:"modify_time_start"`
	ModifyTimeEnd   *int   `json:"modify_time_end"`
}

func (q *DescribeIntegrityReqBody) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.OriginDigest != "" {
		m["origin_digest"] = q.OriginDigest
	}
	if q.Digest != "" {
		m["digest"] = q.Digest
	}
	if q.Exe != "" {
		m["exe"] = utils.TransBackwardsRegex(q.Exe)
	}
	if q.ModifyTimeStart != nil && q.ModifyTimeEnd != nil {
		m["modify_time"] = bson.M{
			"$gte": *q.ModifyTimeStart,
			"$lt":  *q.ModifyTimeEnd,
		}
	}
}

type DescribeIntegrityRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"software_name"`
	Version              string `json:"version" bson:"software_version"`
	OriginDigest         string `json:"origin_digest" bson:"origin_digest"`
	Digest               string `json:"digest" bson:"digest"`
	Exe                  string `json:"exe" bson:"exe"`
	ModifyTime           int    `json:"modify_time" bson:"modify_time"`
}

func DescribeIntegrity(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeIntegrityReqBody{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintIntegrityCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeIntegrityRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeIntegrityRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type DescribeContainerReq struct {
	BasicHostQuery
	State           []string `json:"state"`
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	ImageID         string   `json:"image_id"`
	ImageName       string   `json:"image_name"`
	CreateTimeStart *int     `json:"create_time_start"`
	CreateTimeEnd   *int     `json:"create_time_end"`
}

func (q *DescribeContainerReq) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if len(q.State) > 0 {
		m["state"] = bson.M{
			"$in": q.State,
		}
	}
	if q.ID != "" {
		m["id"] = q.ID
	}
	if q.Name != "" {
		m["name"] = utils.TransBackwardsRegex(q.Name)
	}
	if q.ImageID != "" {
		m["image_id"] = q.ImageID
	}
	if q.ImageName != "" {
		m["image_name"] = q.ImageName
	}
	if q.CreateTimeStart != nil && q.CreateTimeEnd != nil {
		m["create_time"] = bson.M{
			"$gte": *q.CreateTimeStart,
			"$lt":  *q.CreateTimeEnd,
		}
	}
}

type DescribeContainerRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	ContainerID          string `json:"id" bson:"id"`
	Name                 string `json:"name" bson:"name"`
	State                string `json:"state" bson:"state"`
	ImageID              string `json:"image_id" bson:"image_id"`
	ImageName            string `json:"image_name" bson:"image_name"`
	CreateTime           int    `json:"create_time" bson:"create_time"`
}

func DescribeContainer(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeContainerReq{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintContainerCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeContainerRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeContainerRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type DescribeContainerDetailResp struct {
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
	IntranetIP string `json:"intranet_ip"`
	ExtranetIP string `json:"extranet_ip"`
	CreateTime int    `json:"create_time" bson:"create_time"`
	State      string `json:"state" bson:"state"`
	ID         string `json:"id" bson:"id"`
	Name       string `json:"name" bson:"name"`
	ImageID    string `json:"image_id" bson:"image_id"`
	ImageName  string `json:"image_name" bson:"image_name"`
	GroupName  string `json:"group_name" bson:"group_name"`
}

func DescribeContainerDetail(c *gin.Context) {
	agentID := c.Query("agent_id")
	id := c.Query("id")
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	res := coll.FindOne(c, bson.M{"agent_id": agentID})
	if res.Err() != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, res.Err().Error())
		return
	}
	info := asset_center.AgentBasicInfo{}
	err := res.Decode(&info)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	}
	data := DescribeContainerDetailResp{}
	data.Hostname = info.Hostname
	data.Platform = info.Platform
	if len(info.IntranetIPv4) != 0 {
		data.IntranetIP = info.IntranetIPv4[0]
	} else if len(info.IntranetIPv6) != 0 {
		data.IntranetIP = info.IntranetIPv6[0]
	}
	if len(info.ExtranetIPv4) != 0 {
		data.ExtranetIP = info.ExtranetIPv4[0]
	} else if len(info.ExtranetIPv6) != 0 {
		data.ExtranetIP = info.ExtranetIPv6[0]
	}
	coll = infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintContainerCollection)
	res = coll.FindOne(c, bson.M{"agent_id": agentID, "id": id})
	if res.Err() != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, res.Err().Error())
		return
	}
	err = res.Decode(&data)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		common.CreateResponse(c, common.SuccessCode, data)
	}
}

type DescribeContainerStateStatisticsResp struct {
	Created int `json:"created"`
	Running int `json:"running"`
	Exited  int `json:"exited"`
	Unknown int `json:"unknown"`
}

func DescribeContainerStateStatistics(c *gin.Context) {
	coll := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintContainerCollection)
	cursor, err := coll.Aggregate(c, bson.A{
		bson.M{
			"$sort": bson.M{
				"state": 1,
			},
		},
		bson.M{
			"$group": bson.M{
				"_id": "$state",
				"count": bson.M{
					"$sum": 1,
				},
			},
		},
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
		return
	}
	var res []struct {
		State string `bson:"_id"`
		Count int    `bson:"count"`
	}
	err = cursor.All(c, &res)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	}
	data := DescribeContainerStateStatisticsResp{}
	for _, r := range res {
		switch r.State {
		case "created":
			data.Created = r.Count
		case "running":
			data.Running = r.Count
		case "exited":
			data.Exited = r.Count
		case "unknown":
			data.Unknown = r.Count
		}
	}
	common.CreateResponse(c, common.SuccessCode, data)
}

type DescribeVolumeReq struct {
	AgentID string `json:"agent_id" bson:"agent_id"`
}
type DescribeVolumeRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"name"`
	MountPoint           string `json:"mount_point" bson:"mount_point"`
	Fstype               string `json:"fstype" bson:"fstype"`
	Total                string `json:"total" bson:"total"`
	Used                 string `json:"used" bson:"used"`
	Free                 string `json:"free" bson:"free"`
	Usage                string `json:"usage" bson:"usage"`
}

func DescribeVolume(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeVolumeReq{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintVolumeCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   qb,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeVolumeRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeVolumeRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type DescribeNetInterfaceReq struct {
	AgentID string `json:"agent_id" bson:"agent_id"`
}
type DescribeNetInterfaceItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"name"`
	Index                string `json:"index" bson:"index"`
	Addrs                string `json:"addrs" bson:"addrs"`
	HardwareAddr         string `json:"hardware_addr" bson:"hardware_addr"`
	MTU                  string `json:"mtu" bson:"mtu"`
}

func DescribeNetInterface(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeNetInterfaceReq{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintNetInterfaceCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   qb,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeNetInterfaceItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeNetInterfaceItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type DescribeKmodReq struct {
	BasicHostQuery
	State []string `json:"state" binding:"omitempty,dive,oneof=Live Loading Unloading"`
	Name  string   `json:"name"`
}

func (q *DescribeKmodReq) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if len(q.State) > 0 {
		m["state"] = bson.M{
			"$in": q.State,
		}
	}
	if q.Name != "" {
		m["name"] = utils.TransBackwardsRegex(q.Name)
	}
}

type DescribeKmodItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"name"`
	Size                 string `json:"size" bson:"size"`
	Refcount             string `json:"refcount" bson:"refcount"`
	UsedBy               string `json:"used_by" bson:"used_by"`
	State                string `json:"state" bson:"state"`
	Addr                 string `json:"addr" bson:"addr"`
}

func DescribeKmod(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeKmodReq{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintKmodCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeKmodItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeKmodItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}

type DescribeAppGroupRespItem struct {
	Name  string `json:"name" bson:"name"`
	Count int    `json:"count" bson:"count"`
}

func DescribeAppGroup(c *gin.Context) {
	var filter = bson.M{}
	if agent_id, ok := c.GetQuery("agent_id"); ok {
		filter["agent_id"] = agent_id
	}
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintAppCollection)
	cursor, err := collection.Aggregate(context.Background(), bson.A{
		bson.M{
			"$match": filter,
		},
		bson.M{
			"$group": bson.M{
				"_id": "$type",
				"count": bson.M{
					"$sum": 1,
				},
			},
		}, bson.M{
			"$project": bson.M{
				"_id":   false,
				"name":  "$_id",
				"count": true,
			},
		},
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err)
		return
	}
	var res []DescribeAppGroupRespItem
	err = cursor.All(context.Background(), &res)
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err)
	} else {
		common.CreateResponse(c, common.SuccessCode, res)
	}
}

type DescribeAppReq struct {
	BasicHostQuery
	Type string `json:"type" bson:"type"`
	Name string `json:"name" bson:"name"`
}

func (q *DescribeAppReq) MarshalToBson(m bson.M) {
	q.BasicHostQuery.MarshalToBson(m)
	if q.Type != "" {
		m["type"] = q.Type
	}
	if q.Name != "" {
		m["name"] = utils.TransBackwardsRegex(q.Name)
	}
}

type DescribeAppRespItem struct {
	BasicHostInfo        `bson:",inline"`
	BasicFingerprintInfo `bson:",inline"`
	Name                 string `json:"name" bson:"name"`
	Version              string `json:"version" bson:"sversion"`
	Type                 string `json:"type" bson:"type"`
	ContainerID          string `json:"container_id" bson:"container_id"`
	ContainerName        string `json:"container_name" bson:"container_name"`
	PID                  string `json:"pid" bson:"pid"`
	Exe                  string `json:"exe" bson:"exe"`
	Conf                 string `json:"conf" bson:"conf"`
	StartTime            int64  `json:"start_time" bson:"start_time"`
}

func DescribeApp(c *gin.Context) {
	pq := &common.PageRequest{}
	err := c.BindQuery(pq)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	qb := DescribeAppReq{}
	err = c.Bind(&qb)
	if err != nil {
		common.CreateResponse(c, common.ParamInvalidErrorCode, err.Error())
		return
	}
	f := bson.M{}
	qb.MarshalToBson(f)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.FingerprintAppCollection)
	preq := common.PageSearch{
		Page:     utils.Ternary(pq.Page == 0, common.DefaultPage, pq.Page),
		PageSize: utils.Ternary(pq.PageSize == 0, common.DefaultPageSize, pq.PageSize),
		Filter:   f,
		Sorter: bson.M{
			utils.Ternary(pq.OrderKey == "", "_id", pq.OrderKey): utils.Ternary(pq.OrderValue == 0, 1, pq.OrderValue),
		},
	}
	var data []DescribeAppRespItem
	resp, err := common.DBSearchPaginate(collection, preq, func(c *mongo.Cursor) (err error) {
		p := DescribeAppRespItem{}
		err = c.Decode(&p)
		if err == nil {
			data = append(data, p)
		}
		return
	})
	if err != nil {
		common.CreateResponse(c, common.DBOperateErrorCode, err.Error())
	} else {
		CreatePageResponse(c, common.SuccessCode, data, *resp)
	}
}
