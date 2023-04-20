package atask

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/mongodb"
	"github.com/bytedance/Elkeid/server/manager/infra/redis"
	"github.com/bytedance/Elkeid/server/manager/internal/distribute/job"
	. "github.com/bytedance/mockey"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	var err error
	infra.MongoDatabase = "admin"
	if infra.MongoClient, err = mongodb.NewMongoClient("mongodb://127.0.0.1:27017/admin?authSource=admin"); err != nil {
		fmt.Println("NewMongoClient", err.Error())
		panic(-1)
	}

	if infra.Grds, err = redis.NewRedisClient([]string{"127.0.0.1:6379"}, "", ""); err != nil {
		fmt.Println("NEW_REDIS_ERROR", err.Error())
		panic(-1)
	}
	m.Run()
}

func removeAllAgentHB() {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	_, err := col.DeleteMany(context.Background(), bson.M{})
	if err != nil {
		panic(err.Error())
	}
}

func removeAllTask() {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	_, err := col.DeleteMany(context.Background(), bson.M{})
	if err != nil {
		panic(err.Error())
	}
}

func removeAllSubTask() {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	_, err := col.DeleteMany(context.Background(), bson.M{})
	if err != nil {
		panic(err.Error())
	}
}

func addSomeAgentHB(ids []string) {
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	agents := make([]interface{}, 0, len(ids))
	for _, v := range ids {
		hb := def.AgentHBInfo{
			AgentId:          v,
			SourceIp:         "127.0.0.1",
			SourcePort:       5678,
			Tags:             []string{"test"},
			Config:           nil,
			ConfigUpdateTime: time.Now().Unix(),
		}
		agents = append(agents, hb)
	}
	_, err := col.InsertMany(context.Background(), agents)
	if err != nil {
		panic(err.Error())
	}
}

func TestCreateTask(t *testing.T) {
	removeAllAgentHB()
	removeAllTask()
	removeAllSubTask()
	count := 100
	ids := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		ids = append(ids, fmt.Sprintf("agent_id_test_0000%d", i))
	}
	addSomeAgentHB(ids)

	task := AgentTask{}
	task.IDList = ids
	tID, c, err := CreateTask(&task, TypeAgentTask)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	assert.EqualValues(t, c, count)
	time.Sleep(3 * time.Second)

	dbTask, err := GetTaskByID(tID)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	assert.EqualValues(t, TypeAgentTask, dbTask.TaskType)
	assert.EqualValues(t, TaskStatusCreated, dbTask.InnerStatus)
	assert.EqualValues(t, count, len(dbTask.IDList))
	b, _ := json.Marshal(dbTask)
	t.Logf("tID %s", tID)
	t.Logf("%s", string(b))
}

func TestRunTask(t *testing.T) {
	testData := `{
	"tag": "",
	"id_list": ["agent_id_test_00001", "agent_id_test_00002", "agent_id_test_00003", "agent_id_test_00004", "agent_id_test_00005", "agent_id_test_00006", "agent_id_test_00007", "agent_id_test_00008", "agent_id_test_00009", "agent_id_test_000010", "agent_id_test_000011", "agent_id_test_000012", "agent_id_test_000013", "agent_id_test_000014", "agent_id_test_000015", "agent_id_test_000016", "agent_id_test_000017", "agent_id_test_000018", "agent_id_test_000019", "agent_id_test_000020", "agent_id_test_000021", "agent_id_test_000022", "agent_id_test_000023", "agent_id_test_000024", "agent_id_test_000025", "agent_id_test_000026", "agent_id_test_000027", "agent_id_test_000028", "agent_id_test_000029", "agent_id_test_000030", "agent_id_test_000031", "agent_id_test_000032", "agent_id_test_000033", "agent_id_test_000034", "agent_id_test_000035", "agent_id_test_000036", "agent_id_test_000037", "agent_id_test_000038", "agent_id_test_000039", "agent_id_test_000040", "agent_id_test_000041", "agent_id_test_000042", "agent_id_test_000043", "agent_id_test_000044", "agent_id_test_000045", "agent_id_test_000046", "agent_id_test_000047", "agent_id_test_000048", "agent_id_test_000049", "agent_id_test_000050", "agent_id_test_000051", "agent_id_test_000052", "agent_id_test_000053", "agent_id_test_000054", "agent_id_test_000055", "agent_id_test_000056", "agent_id_test_000057", "agent_id_test_000058", "agent_id_test_000059", "agent_id_test_000060", "agent_id_test_000061", "agent_id_test_000062", "agent_id_test_000063", "agent_id_test_000064", "agent_id_test_000065", "agent_id_test_000066", "agent_id_test_000067", "agent_id_test_000068", "agent_id_test_000069", "agent_id_test_000070", "agent_id_test_000071", "agent_id_test_000072", "agent_id_test_000073", "agent_id_test_000074", "agent_id_test_000075", "agent_id_test_000076", "agent_id_test_000077", "agent_id_test_000078", "agent_id_test_000079", "agent_id_test_000080", "agent_id_test_000081", "agent_id_test_000082", "agent_id_test_000083", "agent_id_test_000084", "agent_id_test_000085", "agent_id_test_000086", "agent_id_test_000087", "agent_id_test_000088", "agent_id_test_000089", "agent_id_test_000090", "agent_id_test_000091", "agent_id_test_000092", "agent_id_test_000093", "agent_id_test_000094", "agent_id_test_000095", "agent_id_test_000096", "agent_id_test_000097", "agent_id_test_000098", "agent_id_test_000099", "agent_id_test_0000100"],
	"filter": null,
	"data": {
		"task": {
			"name": "",
			"data": "",
			"token": "",
			"data_type": 0
		}
	},
	"task_name": "",
	"task_id": "1666191349301901000TZugBE",
	"task_type": "Agent_Task",
	"inner_status": "created",
	"task_status": "created",
	"todo_list": ["agent_id_test_00001", "agent_id_test_00002", "agent_id_test_00003", "agent_id_test_00004", "agent_id_test_00005", "agent_id_test_00006", "agent_id_test_00007", "agent_id_test_00008", "agent_id_test_00009", "agent_id_test_000010", "agent_id_test_000011", "agent_id_test_000012", "agent_id_test_000013", "agent_id_test_000014", "agent_id_test_000015", "agent_id_test_000016", "agent_id_test_000017", "agent_id_test_000018", "agent_id_test_000019", "agent_id_test_000020", "agent_id_test_000021", "agent_id_test_000022", "agent_id_test_000023", "agent_id_test_000024", "agent_id_test_000025", "agent_id_test_000026", "agent_id_test_000027", "agent_id_test_000028", "agent_id_test_000029", "agent_id_test_000030", "agent_id_test_000031", "agent_id_test_000032", "agent_id_test_000033", "agent_id_test_000034", "agent_id_test_000035", "agent_id_test_000036", "agent_id_test_000037", "agent_id_test_000038", "agent_id_test_000039", "agent_id_test_000040", "agent_id_test_000041", "agent_id_test_000042", "agent_id_test_000043", "agent_id_test_000044", "agent_id_test_000045", "agent_id_test_000046", "agent_id_test_000047", "agent_id_test_000048", "agent_id_test_000049", "agent_id_test_000050", "agent_id_test_000051", "agent_id_test_000052", "agent_id_test_000053", "agent_id_test_000054", "agent_id_test_000055", "agent_id_test_000056", "agent_id_test_000057", "agent_id_test_000058", "agent_id_test_000059", "agent_id_test_000060", "agent_id_test_000061", "agent_id_test_000062", "agent_id_test_000063", "agent_id_test_000064", "agent_id_test_000065", "agent_id_test_000066", "agent_id_test_000067", "agent_id_test_000068", "agent_id_test_000069", "agent_id_test_000070", "agent_id_test_000071", "agent_id_test_000072", "agent_id_test_000073", "agent_id_test_000074", "agent_id_test_000075", "agent_id_test_000076", "agent_id_test_000077", "agent_id_test_000078", "agent_id_test_000079", "agent_id_test_000080", "agent_id_test_000081", "agent_id_test_000082", "agent_id_test_000083", "agent_id_test_000084", "agent_id_test_000085", "agent_id_test_000086", "agent_id_test_000087", "agent_id_test_000088", "agent_id_test_000089", "agent_id_test_000090", "agent_id_test_000091", "agent_id_test_000092", "agent_id_test_000093", "agent_id_test_000094", "agent_id_test_000095", "agent_id_test_000096", "agent_id_test_000097", "agent_id_test_000098", "agent_id_test_000099", "agent_id_test_0000100"],
	"id_count": 100,
	"distributed_count": 0,
	"job_list": [],
	"action": "",
	"task_user": "",
	"sub_task_created": 0,
	"sub_task_running": 0,
	"sub_task_failed": 0,
	"sub_task_succeed": 0,
	"create_time": 1666191349,
	"update_time": 1666191349
}`
	task := AgentTask{}
	err := json.Unmarshal([]byte(testData), &task)
	if err != nil {
		t.Fatal(err.Error())
	}

	removeAllTask()
	removeAllSubTask()
	_ = infra.DistributedUnLock(task.TaskID)

	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentTaskCollection)
	_, err = col.InsertOne(context.Background(), task)
	if err != nil {
		t.Fatal(err.Error())
	}

	newJobMocker := Mock(job.NewJob).Return("jid-00001", nil).Build()
	distributeJobMocker := Mock(job.DistributeJob).Return().Build()
	finishJobMocker := Mock(job.Finish).Return().Build()

	jID, count, err := RunTask(task.TaskID, 0.1, 0, 5)
	assert.Nil(t, err)
	assert.Equal(t, 10, count)
	assert.NotEqual(t, "", jID)

	newJobMocker.UnPatch()
	distributeJobMocker.UnPatch()
	finishJobMocker.UnPatch()
}
