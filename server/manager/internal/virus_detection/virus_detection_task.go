package virus_detection

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/atask"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type VirusScanTaskDataContent struct {
	Exe     string `json:"exe,omitempty" bson:"exe,omitempty"`
	Mode    string `json:"mode,omitempty" bson:"mode,omitempty"`
	CpuIdle string `json:"cpu_idle,omitempty" bson:"cpu_idle,omitempty"`
	Timeout string `json:"timeout,omitempty" bson:"timeout,omitempty"`
}

// ********************************* Update task status *********************************
func UpdateVirusRunningTaskStatus(c context.Context) {
	var runningTaskList = make([]atask.AgentTask, 0, 50)
	var runningTaskStatus = []string{atask.TaskStatusRunning}
	var nowTime = time.Now().Unix()
	queryJs := bson.M{
		"action":      bson.M{"$in": VirusTaskActionList},
		"task_status": bson.M{"$in": runningTaskStatus},
	}
	collTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	cur, err := collTask.Find(c, queryJs)
	if err != nil {
		ylog.Errorf("func UpdateVirusRunningTaskStatus find running task error", err.Error())
		return
	}

	err = cur.All(c, &runningTaskList)
	if err != nil {
		ylog.Errorf("func UpdateVirusRunningTaskStatus decode running task error", err.Error())
		return
	}

	collSubTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	for _, one := range runningTaskList {
		var res = make([]atask.SubTaskCount, 0, 5)
		pipeline := mongo.Pipeline{
			{primitive.E{Key: "$match", Value: bson.D{primitive.E{Key: "task_id", Value: one.TaskID}}}},
			{primitive.E{Key: "$group", Value: bson.D{
				primitive.E{Key: "_id", Value: "$status"},
				primitive.E{Key: "count", Value: bson.D{primitive.E{Key: "$sum", Value: 1}}}}}},
		}
		opts := options.Aggregate().SetMaxTime(30 * time.Second)
		cursor, err := collSubTask.Aggregate(c, pipeline, opts)
		if err != nil {
			ylog.Errorf("func UpdateVirusRunningTaskStatus Aggregate subtask error",
				"id %s error %s", one.TaskID, err.Error())
			continue
		}

		err = cursor.All(c, &res)
		if err != nil {
			ylog.Errorf("func UpdateVirusRunningTaskStatus decode subtask error",
				"id %s error %s", one.TaskID, err.Error())
			continue
		}

		one.SubTaskCreated = 0
		one.SubTaskSucceed = 0
		one.SubTaskFailed = 0
		one.SubTaskRunning = 0
		ylog.Debugf("task aggregate result", "taskID %s result %+v", one.TaskID, res)
		for _, v := range res {
			switch v.ID {
			case atask.TaskStatusCreated:
				one.SubTaskCreated += v.Count
			case atask.TaskStatusSuccess:
				// one.SubTaskSucceed += v.Count
				one.SubTaskRunning += v.Count
			case atask.TaskStatusFail:
				one.SubTaskFailed += v.Count
			case atask.TaskStatusRunning:
				one.SubTaskRunning += v.Count
			case atask.TaskStatusResultFail:
				one.SubTaskFailed += v.Count
			case atask.TaskStatusResultSuccess:
				one.SubTaskSucceed += v.Count
			default:
				break
			}
		}

		//未取消+未处于新建状态+没有正在运行的子任务
		if one.InnerStatus != atask.TaskStatusStopped && one.DistributedCount != 0 && one.SubTaskRunning == 0 && (one.DistributedCount == (one.SubTaskSucceed + one.SubTaskFailed)) {
			one.TaskStatus = atask.TaskStatusFinished
		} else {
			var taskTimeoutInt int64 = 48 * 3600
			// decode task content
			switch one.Data.Task.DataType {
			case VirusScanDataTypeFull: // full or quick
				var taskContent VirusScanTaskDataContent
				err = json.Unmarshal([]byte(one.Data.Task.Data), &taskContent)
				if err != nil {
					ylog.Errorf("decode virus task content error", "id %s err %s", one.TaskID, err.Error())
				} else {
					tmpInt, cErr := strconv.Atoi(taskContent.Timeout)
					if cErr != nil {
						ylog.Errorf("virus task timeout trans error", "timeOut %s error %s", taskContent.Timeout, cErr.Error())
					} else {
						taskTimeoutInt = int64(tmpInt * 3600)
					}
				}
			case VirusScanDataTypeFile:
				// taskTimeoutInt = 24 * 3600
				taskTimeoutInt = 1800
			}

			// check timeout task
			diffTime := nowTime - one.CreateTime
			if diffTime > taskTimeoutInt {
				one.TaskStatus = atask.TaskStatusFinished
				one.SubTaskFailed = one.SubTaskFailed + one.SubTaskCreated + one.SubTaskRunning
				one.SubTaskCreated = 0
				one.SubTaskRunning = 0
				updateFilter := bson.M{
					"task_id": one.TaskID,
					"status":  bson.M{"$nin": bson.A{atask.TaskStatusResultSuccess, atask.TaskStatusResultFail}},
				}
				updateAction := bson.M{
					"$set": bson.M{
						"status":      atask.TaskStatusFail,
						"task_result": bson.M{"msg": "timeout"},
					},
				}
				// set subtask status
				_, uErr := collSubTask.UpdateMany(c, updateFilter, updateAction)
				if uErr != nil {
					ylog.Errorf("update sub task error", "taskID %s filter %+v error %s", one.TaskID, updateFilter, uErr.Error())
				}

				ylog.Infof("set virus task to timeout", "taskID %s", one.TaskID)
			}
		}

		//write back to db
		_, err = collTask.UpdateOne(c, bson.M{"task_id": one.TaskID}, bson.M{"$set": bson.M{"sub_task_created": one.SubTaskCreated,
			"sub_task_failed": one.SubTaskFailed, "sub_task_succeed": one.SubTaskSucceed, "sub_task_running": one.SubTaskRunning, "task_status": one.TaskStatus}})
		if err != nil {
			ylog.Errorf("func UpdateVirusRunningTaskStatus update task error",
				"id %s error %s", one.TaskID, err.Error())
			continue
		}

		ylog.Infof("func UpdateVirusRunningTaskStatus update task status success",
			"id %s status %s", one.TaskID, one.TaskStatus)
	}
}
