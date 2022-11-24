// Package atask
// CreateTask [ or CreateCtrlTask CreateConfTask CreateTaskTask ] --> create task
// RunTask --> run the task by taskID
//
// status:
//
//  1. task task_status(用于识别整个任务状态):
//     TaskStatusCreated--> TaskStatusRunning [after call the RunTask]
//     --> TaskStatusStopped TaskStatusFinished [ dependent on subtask status ]
//
//  2. task inner_status(用来控制任务下发):
//     TaskStatusCreated --> TaskStatusRunning [after call the RunTask]
//     --> TaskStatusStopped TaskStatusFinished [after all task has been sent]
//
//  3. subTask status:
//     TaskStatusCreated--> TaskStatusRunning[after distribute] --> TaskStatusSuccess TaskStatusFail [after send to agent]
//     --> TaskStatusResultFail TaskStatusResultSuccess [get result from agent]

package atask

import (
	"context"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/distribute/job"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type AgentTask struct {
	Tag    string              `json:"tag" bson:"tag"`
	IDList []string            `json:"id_list" bson:"id_list"`
	Filter *common.FilterQuery `json:"filter" bson:"filter"`
	Data   ConfigRequest       `json:"data" binding:"required" bson:"data"`

	TaskName              string `json:"task_name" bson:"task_name"`
	Action                string `json:"action" bson:"action"`
	TaskUser              string `json:"task_user" bson:"task_user"`
	SubTaskRunningTimeout int64  `json:"subtask_running_timeout" bson:"subtask_running_timeout"` //子任务超时时间

	TaskID           string   `json:"task_id" bson:"task_id"`
	TaskType         string   `json:"task_type" bson:"task_type"`       //TypeAgentConfig TypeAgentTask TypeAgentCtrl
	InnerStatus      string   `json:"inner_status" bson:"inner_status"` //记录下发状态
	TaskStatus       string   `json:"task_status" bson:"task_status"`   //记录任务状态
	ToDoList         []string `json:"todo_list" bson:"todo_list"`
	IDCount          float64  `json:"id_count" bson:"id_count"`
	DistributedCount int      `json:"distributed_count" bson:"distributed_count"` //总共下发总数，包括未执行完成的
	JobList          []string `json:"job_list" bson:"job_list"`

	//count from subTask
	SubTaskCreated int `json:"sub_task_created" bson:"sub_task_created"`
	SubTaskRunning int `json:"sub_task_running" bson:"sub_task_running"`
	SubTaskFailed  int `json:"sub_task_failed" bson:"sub_task_failed"`
	SubTaskSucceed int `json:"sub_task_succeed" bson:"sub_task_succeed"`

	CreateTime int64 `json:"create_time" bson:"create_time" bson:"create_time"`
	UpdateTime int64 `json:"update_time" bson:"update_time" bson:"update_time"`
}

type AgentJobParam struct {
	ConfigTask *AgentTask
	TODOList   []string
	TaskID     string
	JobID      string
}

type SubTaskCount struct {
	ID    string `json:"_id" bson:"_id"`
	Count int    `json:"count" bson:"count"`
}

const AgentJobTimeOut = 60 * 60 // 1 hour
const (
	AgentRebootType = 1060

	TypeAgentConfig = "Agent_Config"
	TypeAgentTask   = "Agent_Task"
	TypeAgentCtrl   = "Agent_Ctrl"

	TaskStatusCreated = "created" //未执行
	TaskStatusRunning = "running" //执行中

	TaskStatusFinished = "finished"  // only for task status and task inner_status
	TaskStatusStopped  = "cancelled" // only for task status and task inner_status

	TaskStatusFail          = "failed"         // only for subtask status
	TaskStatusSuccess       = "succeed"        // only for subtask status
	TaskStatusResultFail    = "result_failed"  // only for subtask status
	TaskStatusResultSuccess = "result_succeed" // only for subtask status
)

func Init() {
	go func() {
		interval := time.Duration(30)
		for {
			ok, _ := infra.DistributedLockWithExpireTime("bg_task_checker", interval*time.Second)
			if ok {
				err := computeAllSubTaskStatus()
				if err != nil {
					ylog.Errorf("computeAllSubTaskStatus", "error %s", err.Error())
				}

				err = computeAllTaskStatus()
				if err != nil {
					ylog.Errorf("computeAllTaskStatus", "error %s", err.Error())
				}
			} else {
				ylog.Infof("DistributedLock", "get bg_task_checker lock failed")
			}

			time.Sleep(interval * time.Second)
		}
	}()
}

// CreateTaskAndRun Create a distributed agent task and run, return the taskID, count of subtask, or error.
func CreateTaskAndRun(request *AgentTask, tType string, concurrence int) (string, int64, error) {
	if request.IDList == nil {
		request.IDList = []string{}
	}
	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)

	var filter bson.M
	if request.Filter == nil {
		filter = bson.M{"$or": []bson.M{{"tags": request.Tag}, {"agent_id": bson.M{"$in": request.IDList}}}}
	} else {
		filter = bson.M{"$or": []bson.M{{"tags": request.Tag}, {"agent_id": bson.M{"$in": request.IDList}}, request.Filter.Transform()}}
	}

	count, err := agentCollection.CountDocuments(context.Background(), filter)
	if err != nil {
		ylog.Errorf("CreateTaskAndRun", "CountDocuments error %s", err.Error())
		return "", 0, err
	}

	cursor, err := agentCollection.Find(context.Background(), filter)
	if err != nil {
		ylog.Errorf("CreateTaskAndRun", "Find error %s", err.Error())
		return "", 0, err
	}

	taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	agentSubTaskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	taskID := fmt.Sprintf(`%d%s`, time.Now().UnixNano(), infra.RandStringBytes(6))

	//写入子任务
	go func() {
		defer func() {
			_ = cursor.Close(context.Background())
		}()

		//Get the global lock.
		ok, err := infra.DistributedLockWithExpireTime(taskID, 5*time.Minute)
		if err != nil {
			ylog.Errorf("CreateTaskAndRun", "DistributedLockWithExpireTime %s error %s", taskID, err.Error())
			return
		}
		if !ok {
			ylog.Errorf("CreateTaskAndRun", "DistributedLockWithExpireTime %s failed.", taskID)
			return
		}

		todoList := make([]string, 0, 1024)
		agentIDMap := make(map[string]bool, 2000)
		writes := make([]mongo.WriteModel, 0, 100)
		for cursor.Next(context.Background()) {
			var hb AgentHBInfo
			err := cursor.Decode(&hb)
			if err != nil {
				ylog.Errorf("CreateTaskAndRun", "%s Decode error %s", taskID, err.Error())
				continue
			}

			//数据同时更新和查询，会导致返回重复数据，确保不重复
			if _, ok := agentIDMap[hb.AgentId]; ok {
				continue
			} else {
				agentIDMap[hb.AgentId] = true
			}

			ylog.Debugf("CreateTaskAndRun", "heartbeat: %#v", hb)
			todoList = append(todoList, hb.AgentId)

			//Write the subTask back to db for reconciliation
			tmp := &AgentSubTask{
				TaskType:   tType,
				AgentID:    hb.AgentId,
				TaskID:     taskID,
				TaskUrl:    "",
				Status:     TaskStatusCreated,
				InsertTime: time.Now().Unix(),
				UpdateTime: time.Now().Unix(),
				TaskResult: "",
			}

			model := mongo.NewInsertOneModel().SetDocument(tmp)
			writes = append(writes, model)
			if len(writes) < 100 {
				continue
			}
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("CreateTaskAndRun", "%s BulkWrite error:%s len:%d", taskID, err.Error(), len(writes))
			} else {
				ylog.Debugf("CreateTaskAndRun", "%s BulkWrite UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", taskID, res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writes = make([]mongo.WriteModel, 0)
		}

		if len(writes) > 0 {
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("CreateTaskAndRun", "%s BulkWrite error:%s len:%d", taskID, err.Error(), len(writes))
			} else {
				ylog.Debugf("CreateTaskAndRun", "%s BulkWrite UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", taskID, res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
		}

		//更新任务状态
		r, err := taskCollection.UpdateOne(
			context.Background(),
			bson.M{"task_id": taskID},
			bson.M{"$set": bson.M{"todo_list": todoList, "id_count": float64(len(todoList)), "update_time": time.Now().Unix()}})
		if err != nil {
			ylog.Errorf("CreateTaskAndRun", "%s error:%s len:%d", taskID, err.Error(), len(writes))
		} else {
			ylog.Debugf("CreateTaskAndRun", "%s BulkWrite UpsertedCount:%d MatchedCount:%d ModifiedCount:%d ", taskID, r.UpsertedCount, r.MatchedCount, r.ModifiedCount)
		}

		err = infra.DistributedUnLockWithRetry(taskID, 3)
		if err != nil {
			ylog.Errorf("CreateTaskAndRun", "DistributedUnLockWithRetry %s error %s", taskID, err.Error())
		}

		//等待一定时间保证任务一定写入成功
		time.Sleep(3 * time.Second)
		jID, _, err := RunTask(taskID, 1, 0, concurrence)
		if err != nil {
			ylog.Errorf("CreateTaskAndRun", "RunTask %s, jobID %s error:%s", taskID, jID, err.Error())
		}
	}()

	//将此次任务记录写回db
	request.InnerStatus = TaskStatusCreated
	request.TaskStatus = TaskStatusCreated
	request.ToDoList = []string{}
	request.TaskType = tType
	request.JobList = []string{}
	request.CreateTime = time.Now().Unix()
	request.UpdateTime = time.Now().Unix()
	request.IDCount = 0
	request.TaskID = taskID
	request.DistributedCount = 0

	_, err = taskCollection.InsertOne(context.Background(), request)
	if err != nil {
		ylog.Errorf("CreateTaskAndRun", "%s InsertOne error %s", taskID, err.Error())
	}
	return request.TaskID, count, nil
}

// CreateTask Create a distributed agent task and return taskID, count of subtask, or error.
func CreateTask(request *AgentTask, tType string) (string, int64, error) {
	if request.IDList == nil {
		request.IDList = []string{}
	}
	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	var filter bson.M
	if request.Filter == nil {
		filter = bson.M{"$or": []bson.M{{"tags": request.Tag}, {"agent_id": bson.M{"$in": request.IDList}}}}
	} else {
		filter = bson.M{"$or": []bson.M{{"tags": request.Tag}, {"agent_id": bson.M{"$in": request.IDList}}, request.Filter.Transform()}}
	}

	count, err := agentCollection.CountDocuments(context.Background(), filter)
	if err != nil {
		ylog.Errorf("createTask", "CountDocuments error %s", err.Error())
		return "", 0, err
	}

	cursor, err := agentCollection.Find(context.Background(), filter)
	if err != nil {
		ylog.Errorf("createTask", "Find error %s", err.Error())
		return "", 0, err
	}

	taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	agentSubTaskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	writeOption := &options.BulkWriteOptions{}
	writeOption.SetOrdered(false)
	taskID := fmt.Sprintf(`%d%s`, time.Now().UnixNano(), infra.RandStringBytes(6))

	//写入子任务
	go func() {
		defer func() {
			_ = cursor.Close(context.Background())
		}()

		//Get the global lock.
		ok, err := infra.DistributedLockWithExpireTime(taskID, 5*time.Minute)
		if err != nil {
			ylog.Errorf("createTask", "DistributedLockWithExpireTime %s error %s", taskID, err.Error())
			return
		}
		if !ok {
			ylog.Errorf("createTask", "DistributedLockWithExpireTime %s failed.", taskID)
			return
		}

		defer func() {
			err = infra.DistributedUnLockWithRetry(taskID, 3)
			if err != nil {
				ylog.Errorf("createTask", "DistributedUnLockWithRetry %s error %s", taskID, err.Error())
			}
		}()

		todoList := make([]string, 0, 1024)
		agentIDMap := make(map[string]bool, 2000)
		writes := make([]mongo.WriteModel, 0, 100)
		for cursor.Next(context.Background()) {
			var hb AgentHBInfo
			err := cursor.Decode(&hb)
			if err != nil {
				ylog.Errorf("createTask", "%s Decode error %s", taskID, err.Error())
				continue
			}

			//数据同时更新和查询，会导致返回重复数据，确保不重复
			if _, ok := agentIDMap[hb.AgentId]; ok {
				continue
			} else {
				agentIDMap[hb.AgentId] = true
			}

			ylog.Debugf("createTask", "heartbeat: %#v", hb)
			todoList = append(todoList, hb.AgentId)

			//Write the subTask back to db for reconciliation
			tmp := &AgentSubTask{
				TaskType:   tType,
				AgentID:    hb.AgentId,
				TaskID:     taskID,
				TaskUrl:    "",
				Status:     TaskStatusCreated,
				InsertTime: time.Now().Unix(),
				UpdateTime: time.Now().Unix(),
				TaskResult: "",
			}

			model := mongo.NewInsertOneModel().SetDocument(tmp)
			writes = append(writes, model)
			if len(writes) < 100 {
				continue
			}
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("createTask", "%s BulkWrite error:%s len:%d", taskID, err.Error(), len(writes))
			} else {
				ylog.Debugf("createTask", "%s BulkWrite UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", taskID, res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
			writes = make([]mongo.WriteModel, 0)
		}

		if len(writes) > 0 {
			res, err := agentSubTaskCollection.BulkWrite(context.Background(), writes, writeOption)
			if err != nil {
				ylog.Errorf("createTask", "%s BulkWrite error:%s len:%d", taskID, err.Error(), len(writes))
			} else {
				ylog.Debugf("createTask", "%s BulkWrite UpsertedCount:%d InsertedCount:%d ModifiedCount:%d ", taskID, res.UpsertedCount, res.InsertedCount, res.ModifiedCount)
			}
		}

		//更新任务状态
		r, err := taskCollection.UpdateOne(
			context.Background(),
			bson.M{"task_id": taskID},
			bson.M{"$set": bson.M{"todo_list": todoList, "id_count": float64(len(todoList)), "update_time": time.Now().Unix()}})
		if err != nil {
			ylog.Errorf("subTaskWriter_BulkWrite", "%s error:%s len:%d", taskID, err.Error(), len(writes))
		} else {
			ylog.Debugf("subTaskWriter_BulkWrite", "%s BulkWrite UpsertedCount:%d MatchedCount:%d ModifiedCount:%d ", taskID, r.UpsertedCount, r.MatchedCount, r.ModifiedCount)
		}
	}()

	//将此次任务记录写回db
	request.InnerStatus = TaskStatusCreated
	request.TaskStatus = TaskStatusCreated
	request.ToDoList = []string{}
	request.TaskType = tType
	request.JobList = []string{}
	request.CreateTime = time.Now().Unix()
	request.UpdateTime = time.Now().Unix()
	request.IDCount = 0
	request.TaskID = taskID
	request.DistributedCount = 0

	_, err = taskCollection.InsertOne(context.Background(), request)
	if err != nil {
		ylog.Errorf("createTask", "%s InsertOne error %s", taskID, err.Error())
	}
	return request.TaskID, count, nil
}

func CreateCtrlTask(t *AgentTask) (string, int64, error) {
	return CreateTask(t, TypeAgentTask)
}

func CreateConfTask(t *AgentTask) (string, int64, error) {
	return CreateTask(t, TypeAgentConfig)
}

func CreateTaskTask(t *AgentTask) (string, int64, error) {
	return CreateTask(t, TypeAgentTask)
}

// CancelTask cancel a task and set the task_status and inner_status to TaskStatusStopped.
func CancelTask(taskID string) error {
	ok, err := infra.DistributedLockWithExpireTime(taskID, AgentJobTimeOut*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("jobs is running, please try later")
	}
	defer func() {
		err := infra.DistributedUnLock(taskID)
		if err != nil {
			ylog.Errorf("CancelTask", "DistributedUnLock error %s", err.Error())
		}
	}()

	taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	_, err = taskCollection.UpdateOne(context.Background(), bson.M{"task_id": taskID},
		bson.M{"$set": bson.M{"update_time": time.Now().Unix(), "task_status": TaskStatusStopped, "inner_status": TaskStatusStopped}})
	if err != nil {
		return err
	}
	return nil
}

// RunTask run a task and return jobID, count of subtask, or error.
// If rollPercent > 0 , use rollPercent, else use runCount.
// Concurrence controls the concurrency of each manager instance, so the true concurrency is concurrence * number of instances.
func RunTask(taskID string, rollPercent float64, runCount int, concurrence int) (string, int, error) {
	if rollPercent <= 0 && runCount <= 0 {
		return "", 0, errors.New("rollPercent and runCount is 0")
	}
	//Get the global lock.
	ok, err := infra.DistributedLockWithExpireTime(taskID, AgentJobTimeOut*time.Second)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, errors.New("jobs is not not initialized or cannot be executed concurrently, please try later")
	}

	//Calculate the count of machines processed by this job
	var dbTask AgentTask
	taskCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	err = taskCollection.FindOne(context.Background(), bson.M{"task_id": taskID}).Decode(&dbTask)
	if err != nil {
		err1 := infra.DistributedUnLock(taskID)
		if err1 != nil {
			ylog.Errorf("RunTask", "DistributedUnLock %s, error %s", taskID, err1.Error())
		}
		return "", 0, err
	}

	if dbTask.InnerStatus == TaskStatusStopped || dbTask.InnerStatus == TaskStatusFinished {
		ylog.Errorf("RunTask", "taskID %s, InnerStatus %s", taskID, dbTask.InnerStatus)
		err1 := infra.DistributedUnLock(taskID)
		if err1 != nil {
			ylog.Errorf("RunTask", "DistributedUnLock %s, error %s", taskID, err1.Error())
		}
		return "", 0, errors.New("task is finished/stopped or the todo_list is empty")
	}

	if len(dbTask.ToDoList) == 0 {
		_, err := taskCollection.UpdateOne(context.Background(), bson.M{"task_id": dbTask.TaskID}, bson.M{"$set": bson.M{"update_time": dbTask.UpdateTime, "inner_status": TaskStatusFinished}})
		if err != nil {
			ylog.Errorf("RunTask", "UpdateOne %s, error %s", taskID, err.Error())
		}
		err1 := infra.DistributedUnLock(taskID)
		if err1 != nil {
			ylog.Errorf("RunTask", "DistributedUnLock %s, error %s", taskID, err1.Error())
		}
		return "", 0, errors.New("task is finished/stopped or the todo_list is empty")
	}

	var nCount int
	if rollPercent > 0 {
		if nCount = int(dbTask.IDCount * rollPercent); nCount == 0 {
			nCount = nCount + 1
		}
	} else {
		nCount = runCount
	}
	if nCount < len(dbTask.ToDoList) {
		dbTask.InnerStatus = TaskStatusRunning
	} else {
		nCount = len(dbTask.ToDoList)
		dbTask.InnerStatus = TaskStatusFinished
	}
	todoList := dbTask.ToDoList[:nCount]
	dbTask.ToDoList = dbTask.ToDoList[nCount:len(dbTask.ToDoList)]
	dbTask.DistributedCount = dbTask.DistributedCount + len(todoList)

	//Create the jod and distribute.
	jID, err := job.NewJob(dbTask.TaskType, concurrence, AgentJobTimeOut, true)
	if err != nil {
		err1 := infra.DistributedUnLock(taskID)
		if err1 != nil {
			ylog.Errorf("RunTask", "DistributedUnLock %s, error %s", taskID, err1.Error())
		}
		return "", 0, err
	}

	jobParm := AgentJobParam{ConfigTask: &dbTask, TODOList: todoList, TaskID: dbTask.TaskID, JobID: jID}
	//Asynchronous distribution
	go func() {
		job.DistributeJob(jID, dbTask.TaskType, jobParm)
		job.Finish(jID)
		err1 := infra.DistributedUnLock(taskID)
		if err1 != nil {
			ylog.Errorf("RunTask", "DistributedUnLock %s, error %s", taskID, err1.Error())
		}
	}()

	dbTask.JobList = append(dbTask.JobList, jID)
	dbTask.UpdateTime = time.Now().Unix()
	_, err = taskCollection.UpdateOne(context.Background(), bson.M{"task_id": dbTask.TaskID},
		bson.M{"$set": bson.M{"todo_list": dbTask.ToDoList, "update_time": dbTask.UpdateTime, "task_status": TaskStatusRunning,
			"inner_status": dbTask.InnerStatus, "distributed_count": dbTask.DistributedCount, "job_list": dbTask.JobList}})
	if err != nil {
		ylog.Errorf("RunTask", "UpdateOne %s, error %s", taskID, err.Error())
	}
	return jID, len(todoList), nil
}

func GetTaskByID(taskID string) (*AgentTask, error) {
	var task AgentTask
	collTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	err := collTask.FindOne(context.Background(), bson.M{"task_id": taskID}).Decode(&task)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}

	//task.ToDoList = []string{}
	return &task, nil
}

func computeAllSubTaskStatus() error {
	collSubTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	updateRes, err := collSubTask.UpdateMany(context.Background(),
		bson.M{"task_type": TypeAgentTask, "status": TaskStatusSuccess, "job_time_out_time": bson.M{"$lt": time.Now().Unix(), "$gt": 0}},
		bson.M{"$set": bson.M{"status": TaskStatusResultFail, "status_msg": "Timeout waiting for agent response", "update_time": time.Now().Unix()}})
	if err != nil {
		return err
	} else {
		ylog.Debugf("computeTaskStat", "UpdateMany MatchedCount %d, ModifiedCount %d, UpsertedCount %d", updateRes.MatchedCount, updateRes.ModifiedCount, updateRes.UpsertedCount)
	}
	return nil
}

func computeAllTaskStatus() error {
	taskCol := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	cur, err := taskCol.Find(context.Background(), bson.M{"task_status": TaskStatusRunning})
	if err != nil {
		return err
	}
	defer func() {
		if dErr := cur.Close(context.Background()); dErr != nil {
			ylog.Errorf("computeAllTaskStatus", "cursor close error %s", dErr.Error())
		}
	}()

	for cur.Next(context.Background()) {
		task := AgentTask{}
		err = cur.Decode(&task)
		if err != nil {
			ylog.Errorf("computeAllTaskStatus", "cursor Decode error %s", err.Error())
			continue
		}
		err = computeTaskStat(&task)
		if err != nil {
			ylog.Errorf("computeAllTaskStatus", "computeSubTaskStat error %s", err.Error())
		}
	}
	return nil
}

func computeTaskStat(task *AgentTask) error {
	var res = make([]SubTaskCount, 5)
	collSubTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	//处理超时
	if task.SubTaskRunningTimeout != 0 {
		//time out
		timeOut := time.Now().Add(time.Duration(-task.SubTaskRunningTimeout) * time.Second).Unix()
		updateRes, err := collSubTask.UpdateMany(context.Background(),
			bson.M{"task_id": task.TaskID, "task_type": TypeAgentTask, "status": TaskStatusSuccess, "job_start_time": bson.M{"$lt": timeOut}},
			bson.M{"$set": bson.M{"status": TaskStatusResultFail, "status_msg": "Timeout waiting for agent response", "update_time": time.Now().Unix()}})
		if err != nil {
			return err
		} else {
			ylog.Debugf("computeTaskStat", "UpdateMany MatchedCount %d, ModifiedCount %d, UpsertedCount %d", updateRes.MatchedCount, updateRes.ModifiedCount, updateRes.UpsertedCount)
		}

		updateRes, err = collSubTask.UpdateMany(context.Background(),
			bson.M{"task_id": task.TaskID, "task_type": bson.M{"$in": []string{TypeAgentTask, TypeAgentConfig}}, "status": TaskStatusRunning, "job_start_time": bson.M{"$lt": timeOut}},
			bson.M{"$set": bson.M{"status": TaskStatusFail, "status_msg": "Timed out sending request to agent center", "update_time": time.Now().Unix()}})
		if err != nil {
			return err
		} else {
			ylog.Debugf("computeTaskStat", "UpdateMany MatchedCount %d, ModifiedCount %d, UpsertedCount %d", updateRes.MatchedCount, updateRes.ModifiedCount, updateRes.UpsertedCount)
		}
	}

	//计算任务状态
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"task_id", task.TaskID}}}},
		{{"$group", bson.D{{"_id", "$status"}, {"count", bson.D{{"$sum", 1}}}}}},
	}
	opts := options.Aggregate().SetMaxTime(15 * time.Second)
	cursor, err := collSubTask.Aggregate(context.TODO(), pipeline, opts)
	if err != nil {
		return err
	}

	err = cursor.All(context.Background(), &res)
	if err != nil {
		return err
	}

	task.SubTaskCreated = 0
	task.SubTaskSucceed = 0
	task.SubTaskFailed = 0
	task.SubTaskRunning = 0
	//reboot_agent task 没有回包
	if task.TaskType == TypeAgentTask && task.Action != "reboot_agent" {
		for _, v := range res {
			switch v.ID {
			case TaskStatusCreated:
				task.SubTaskCreated += v.Count
			case TaskStatusSuccess:
				task.SubTaskRunning += v.Count
			case TaskStatusFail:
				task.SubTaskFailed += v.Count
			case TaskStatusRunning:
				task.SubTaskRunning += v.Count
			case TaskStatusResultFail:
				task.SubTaskFailed += v.Count
			case TaskStatusResultSuccess:
				task.SubTaskSucceed += v.Count
			default:
				break
			}
		}
	} else {
		for _, v := range res {
			switch v.ID {
			case TaskStatusCreated:
				task.SubTaskCreated += v.Count
			case TaskStatusSuccess:
				task.SubTaskSucceed += v.Count
			case TaskStatusFail:
				task.SubTaskFailed += v.Count
			case TaskStatusRunning:
				task.SubTaskRunning += v.Count
			default:
				break
			}
		}
	}

	//未处于新建状态+任务未处于运行转态+没有正在运行的子任务且下发总数等于执行总数
	if task.InnerStatus != TaskStatusCreated && task.InnerStatus != TaskStatusRunning && task.DistributedCount != 0 && task.SubTaskRunning == 0 && (task.DistributedCount == (task.SubTaskSucceed + task.SubTaskFailed)) {
		task.TaskStatus = TaskStatusFinished
	}

	//write back db
	collTask := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	_, err = collTask.UpdateOne(context.Background(),
		bson.M{"task_id": task.TaskID},
		bson.M{"$set": bson.M{"sub_task_created": task.SubTaskCreated, "sub_task_failed": task.SubTaskFailed, "sub_task_succeed": task.SubTaskSucceed, "sub_task_running": task.SubTaskRunning, "task_status": task.TaskStatus, "update_time": time.Now().Unix()}})
	if err != nil {
		ylog.Errorf("GetTaskByID", err.Error())
	}

	ylog.Infof("computeTaskStat", "task id %s status %s", task.TaskID, task.TaskStatus)
	return nil
}
