// Package atask
// default agent subtask response format:
//
//	{
//	       "status" : "succeed",      //succeed or failed
//	       "msg" : "No such file or directory",      //
//	       "token" : "c5mej1rc77ubvhrfifkg",   //the token
//	}
package atask

import (
	"context"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"go.mongodb.org/mongo-driver/bson"
)

type AgentSubTask struct {
	AppendData     map[string]interface{} `json:"append_data" bson:"append_data"`        //创建子任务携带额外信息
	TaskType       string                 `json:"task_type" bson:"task_type" `           //TypeAgentConfig TypeAgentTask TypeAgentCtrl
	TaskDataType   int32                  `json:"task_data_type" bson:"task_data_type" ` //
	AgentID        string                 `json:"agent_id" bson:"agent_id" `
	TaskID         string                 `json:"task_id" bson:"task_id" `
	JobID          string                 `json:"job_id" bson:"job_id" `      //子任务对应jobID（如果有）
	TaskData       interface{}            `json:"task_data" bson:"task_data"` //任务下发ac json body
	TaskUrl        string                 `json:"task_url" bson:"task_url"`   //任务下发ac url
	Token          string                 `json:"token" bson:"token"`
	Status         string                 `json:"status" bson:"status"`         //子任务状态 TaskStatusCreated|TaskStatusRunning|TaskStatusSuccess|TaskStatusFail|TaskStatusResultFail|TaskStatusResultSuccess
	StatusMsg      string                 `json:"status_msg" bson:"status_msg"` //状态说明信息
	InsertTime     int64                  `json:"insert_time" bson:"insert_time"`
	UpdateTime     int64                  `json:"update_time" bson:"update_time"`
	JobTimeOutTime int64                  `json:"job_time_out_time" bson:"job_time_out_time"` //子任务超时时间
	JobStartTime   int64                  `json:"job_start_time" bson:"job_start_time"`       //任务开始时间（指开始下发到AC的时间）
	TaskResult     interface{}            `json:"task_result" bson:"task_result"`             //agent上报数据
	TaskResp       string                 `json:"task_resp" bson:"task_resp"`                 //任务下发ac response
}

type ResFunc func(data map[string]interface{})

var ResMap = map[string]ResFunc{}

func ResFuncOld(data map[string]interface{}) {
	//5100: 主动触发资产数据扫描
	//8010: 基线扫描
	stUpdater := map[string]interface{}{"token": data["token"]}
	stUpdater["task_result"] = data
	stUpdater["status"] = TaskStatusSuccess
	stUpdater["status_msg"] = data["msg"]
	if status, ok := data["status"].(string); !ok || status != "succeed" {
		stUpdater["status"] = TaskStatusFail
	}
	dbtask.SubTaskUpdateAsyncWrite(stUpdater)
}

func DefaultResFunc(data map[string]interface{}) {
	stUpdater := map[string]interface{}{"token": data["token"]}
	stUpdater["task_result"] = data
	stUpdater["status"] = TaskStatusResultSuccess
	stUpdater["status_msg"] = data["msg"]
	if status, ok := data["status"].(string); !ok || status != "succeed" {
		stUpdater["status"] = TaskStatusResultFail
	}
	dbtask.SubTaskUpdateAsyncWrite(stUpdater)
}

func RegistryResFunc(dt string, f ResFunc) {
	if f == nil {
		f = DefaultResFunc
	}
	ResMap[dt] = f
}

func init() {
	RegistryResFunc("5100", nil) //5100: 主动触发资产数据扫描
	RegistryResFunc("8010", nil) //8010: 基线扫描
	RegistryResFunc("6000", nil) //6000: 文件隔离
}

func PushSubTask(data map[string]interface{}) {
	//recover all panic
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		if err, ok := r.(error); ok {
			ylog.Errorf("PushSubTask", "error %s", err.Error())
		}
	}()

	if token, ok := data["token"].(string); !ok || token == "" {
		return
	}

	if sdt, ok := data["data_type"].(string); ok {
		if f, ok1 := ResMap[sdt]; ok1 {
			ylog.Debugf("complexSubTaskAsyncWrite", "get data %s %#v", sdt, data)
			f(data)
			return
		}
	}

	stUpdater := map[string]interface{}{"token": data["token"]}
	stUpdater["task_result"] = data
	dbtask.SubTaskUpdateAsyncWrite(stUpdater)
}

type AgentSubTaskToken struct {
	Token string `json:"token" bson:"token"`
}

func GetSubTaskTokenList(ctx context.Context, taskID string) []string {
	var retList = make([]string, 0, 100)
	var taskList = make([]AgentSubTaskToken, 0)
	collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	cur, err := collection.Find(ctx, bson.M{"task_id": taskID})
	if err != nil {
		ylog.Errorf("func GetSubTaskInfoForVirus find error", err.Error())
		return retList
	}

	err = cur.All(ctx, &taskList)
	if err != nil {
		ylog.Errorf("func GetSubTaskInfoForVirus decode error", err.Error())
		return retList
	}

	for _, one := range taskList {
		retList = append(retList, one.Token)
	}

	return retList
}
