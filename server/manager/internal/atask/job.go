package atask

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/aconfig"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/bytedance/Elkeid/server/manager/internal/distribute/job"
	"github.com/levigross/grequests"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

// AgentControlDistribute for old version config
func AgentControlDistribute(Jid string, k, v interface{}) (interface{}, error) {
	var (
		name          = k.(string)
		jobParam      = v.(AgentJobParam)
		jobs          = make([]job.JobArgs, 0)
		defaultConfig []AgentConfigMsg
	)
	// Load default policy from db.
	if name == TypeAgentConfig {
		defaultConfig = aconfig.GetDefaultConfig()
	}

	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := agentCollection.Find(context.Background(),
		bson.M{"agent_id": bson.M{"$in": jobParam.TODOList}})
	if err != nil {
		ylog.Errorf("AgentControlDistribute", "%s error %s.", Jid, err.Error())
		return nil, err
	}

	defer func() {
		if dErr := cursor.Close(context.Background()); dErr != nil {
			ylog.Errorf("AgentControlDistribute", "%s cursor.Close error %s", Jid, dErr.Error())
		}
	}()

	agentIDMap := make(map[string]bool, 2000)
	for cursor.Next(context.Background()) {
		var hb AgentHBInfo
		err := cursor.Decode(&hb)
		if err != nil {
			ylog.Errorf("agentTaskDistribute", "%s error %s.", Jid, err.Error())
			continue
		}

		// Data update and query at the same time will cause duplicate data to be returned. Ensure that the data is not duplicated
		if _, ok := agentIDMap[hb.AgentId]; ok {
			continue
		} else {
			agentIDMap[hb.AgentId] = true
		}

		var argv map[string]interface{}
		token := GenerateToken()
		switch name {
		case TypeAgentConfig:
			// If the policy does not exist, use the default policy.
			if hb.Config == nil || len(hb.Config) == 0 {
				hb.Config = defaultConfig
			}

			// Update policy.
			updateConfig(jobParam.ConfigTask, &hb)
			argv = map[string]interface{}{"command": map[string]interface{}{"config": hb.Config}}

			// Write back to db asynchronously.
			dbtask.HBAsyncWrite(&ConnStat{
				AgentInfo: map[string]interface{}{
					"agent_id":           hb.AgentId,
					"config_update_time": time.Now().Unix(),
					"config":             hb.Config,
				},
				PluginsInfo: nil,
			})
		case TypeAgentTask:
			item := AgentTaskMsg{
				Name:     jobParam.ConfigTask.Data.Task.Name,
				Data:     jobParam.ConfigTask.Data.Task.Data,
				DataType: jobParam.ConfigTask.Data.Task.DataType,
				Token:    token,
			}
			argv = map[string]interface{}{"command": map[string]interface{}{"task": item}}
		case TypeAgentCtrl:
			argv = map[string]interface{}{"command": map[string]interface{}{"agent_ctrl": jobParam.ConfigTask.Data.AgentCtrl}}
		default:
			ylog.Errorf("agentTaskDistribute", "taskType not support %s", name)
			continue
		}

		// Write the subTask back to db for reconciliation
		subtask := make(map[string]interface{}, 7)
		subtask["task_id"] = jobParam.TaskID
		subtask["agent_id"] = hb.AgentId
		subtask["task_data"] = argv
		subtask["token"] = token
		subtask["status"] = TaskStatusRunning
		subtask["job_start_time"] = time.Now().Unix()
		subtask["job_id"] = jobParam.JobID
		subtask["update_time"] = time.Now().Unix()
		dbtask.SubTaskUpdateAsyncWrite(subtask)

		addr := fmt.Sprintf("%s:%d", hb.SourceIp, hb.SourcePort)
		argv["agent_id"] = hb.AgentId
		innerArgv := map[string]interface{}{"token": token, "argv": argv}
		ja := job.JobArgs{
			Name:    name,
			Host:    addr,
			Args:    innerArgv,
			Scheme:  job.ApiMap[name]["scheme"].(string),
			Method:  job.ApiMap[name]["method"].(string),
			Timeout: job.ApiMap[name]["timeout"].(int),
			Path:    job.ApiMap[name]["path"].(string),
		}
		jobs = append(jobs, ja)
	}

	return jobs, nil
}

// AgentControlDo for old version config
func AgentControlDo(Jid string, args interface{}) (interface{}, error) {
	var (
		r      *grequests.Response
		err    error
		result string
	)
	ja := job.JobArgs{
		Args: make(map[string]interface{}),
	}
	err = json.Unmarshal([]byte(args.(string)), &ja)
	if err != nil {
		ylog.Infof("agentControlDo", "[api_job] %s do error: %s", Jid, err.Error())
		return nil, err
	}

	innerArgv, ok := ja.Args.(map[string]interface{})
	if !ok {
		ylog.Errorf("agentControlDo", "[api_job] %s AgentJobInnerParam parse error", Jid)
		return nil, err
	}

	url := fmt.Sprintf("%s://%s%s", ja.Scheme, ja.Host, ja.Path)
	ylog.Infof("agentControlDo", "[api_jobs] do %s : %s %s", Jid, url, args.(string))

	option := midware.SvrAuthRequestOption()
	option.JSON = innerArgv["argv"]
	option.RequestTimeout = time.Duration(ja.Timeout) * time.Second

	switch ja.Method {
	case job.HttpMethodGet:
		r, err = grequests.Get(url, option)
	case job.HttpMethodPost:
		r, err = grequests.Post(url, option)
	default:
		return nil, errors.New("request method not support")
	}
	if err != nil || r.StatusCode != 200 {
		ylog.Errorf("agentControlDo", "%s url: %s; args: %s; err: %#v res: %#v", Jid, url, args.(string), err, r)
	}

	subTask := make(map[string]interface{}, 4)
	subTask["token"] = innerArgv["token"].(string)
	subTask["task_url"] = url
	subTask["status"] = TaskStatusSuccess
	subTask["update_time"] = time.Now().Unix()
	// http connection error
	if err != nil {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = err.Error()
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	// http error
	if !r.Ok {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("StatusCode is %d", r.StatusCode)
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	svrRsp := &SvrResponse{}
	err = json.Unmarshal(r.Bytes(), svrRsp)
	// repose parse error
	if err != nil {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("%s Unmarshal error %s", r.String(), err.Error())
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	// repose code error
	if svrRsp.Code != 0 {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("svr response error %s", r.String())
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
	}

	// success
	subTask["task_resp"] = r.String()
	dbtask.SubTaskUpdateAsyncWrite(subTask)
	return job.JobResWithArgs{Args: &ja, Response: r, Result: result}, err
}

// AgentControlDistributeV2 for new version config
func AgentControlDistributeV2(Jid string, k, v interface{}) (interface{}, error) {
	var (
		name     = k.(string)
		jobParam = v.(AgentJobParam)
		jobs     = make([]job.JobArgs, 0)
	)
	agentCollection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
	cursor, err := agentCollection.Find(context.Background(),
		bson.M{"agent_id": bson.M{"$in": jobParam.TODOList}})
	if err != nil {
		ylog.Errorf("agentTaskDistribute", "%s, error %s", Jid, err.Error())
		return nil, err
	}

	defer func() {
		if dErr := cursor.Close(context.Background()); dErr != nil {
			ylog.Errorf("AgentControlDistribute", "%s cursor.Close error %s", Jid, dErr.Error())
		}
	}()
	agentIDMap := make(map[string]bool, 2000)
	for cursor.Next(context.Background()) {
		var hb AgentHBInfo
		err := cursor.Decode(&hb)
		if err != nil {
			ylog.Errorf("agentTaskDistribute", "%s, error %s", Jid, err.Error())
			continue
		}

		// Data update and query at the same time will cause duplicate data to be returned. Ensure that the data is not duplicated
		if _, ok := agentIDMap[hb.AgentId]; ok {
			continue
		} else {
			agentIDMap[hb.AgentId] = true
		}

		// Write the subTask back to db for reconciliation
		subtask := make(map[string]interface{}, 7)
		subtask["task_id"] = jobParam.TaskID
		subtask["agent_id"] = hb.AgentId
		subtask["status"] = TaskStatusRunning
		subtask["job_id"] = jobParam.JobID
		subtask["update_time"] = time.Now().Unix()
		subtask["job_start_time"] = time.Now().Unix()
		dbtask.SubTaskUpdateAsyncWrite(subtask)

		innerArgv := map[string]interface{}{"agent_id": hb.AgentId, "task_id": jobParam.TaskID}
		ja := job.JobArgs{
			Name:    name,
			Host:    fmt.Sprintf("%s:%d", hb.SourceIp, hb.SourcePort),
			Args:    innerArgv,
			Scheme:  job.ApiMap[name]["scheme"].(string),
			Method:  job.ApiMap[name]["method"].(string),
			Timeout: job.ApiMap[name]["timeout"].(int),
			Path:    job.ApiMap[name]["path"].(string),
		}
		jobs = append(jobs, ja)
	}

	return jobs, nil
}

// AgentControlDoV2 for new version config. config load from task_data
func AgentControlDoV2(Jid string, args interface{}) (interface{}, error) {
	var (
		r   *grequests.Response
		err error
	)
	ja := job.JobArgs{
		Args: make(map[string]interface{}),
	}
	err = json.Unmarshal([]byte(args.(string)), &ja)
	if err != nil {
		ylog.Infof("agentControlDoV2", "[api_job] %s, do error: %s", Jid, err.Error())
		return nil, err
	}

	innerArgv, ok := ja.Args.(map[string]interface{})
	if !ok {
		ylog.Errorf("agentControlDoV2", "[api_job] %s AgentJobInnerParam parse error", Jid)
		return nil, err
	}

	url := fmt.Sprintf("%s://%s%s", ja.Scheme, ja.Host, ja.Path)
	ylog.Infof("agentControlDoV2", "[api_jobs] %s do: %s %s", Jid, url, args.(string))

	subTask := make(map[string]interface{}, 4)
	subTask["task_id"] = innerArgv["task_id"]
	subTask["agent_id"] = innerArgv["agent_id"]
	subTask["task_url"] = url
	subTask["status"] = TaskStatusSuccess
	subTask["update_time"] = time.Now().Unix()

	dbSubTask := map[string]interface{}{}
	col := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentSubTaskCollection)
	err = col.FindOne(context.Background(), bson.M{"agent_id": innerArgv["agent_id"], "task_id": innerArgv["task_id"]}).Decode(&dbSubTask)
	if err != nil {
		ylog.Errorf("agentControlDoV2", "%s url: %s; args: %s; err: %s", Jid, url, args.(string), err.Error())

		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = err.Error()
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja}, err
	}

	option := midware.SvrAuthRequestOption()
	option.JSON = dbSubTask["task_data"]
	option.RequestTimeout = time.Duration(ja.Timeout) * time.Second

	switch ja.Method {
	case job.HttpMethodGet:
		r, err = grequests.Get(url, option)
	case job.HttpMethodPost:
		r, err = grequests.Post(url, option)
	default:
		return nil, errors.New("request method not support")
	}
	if err != nil || r.StatusCode != 200 {
		ylog.Errorf("agentControlDoV2", "%s, url: %s; args: %s; err: %#v res: %#v", Jid, url, args.(string), err, r)
	}

	// http connection error
	if err != nil {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = err.Error()
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r}, err
	}

	// http error
	if !r.Ok {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("StatusCode is %d", r.StatusCode)
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r}, err
	}

	svrRsp := &SvrResponse{}
	err = json.Unmarshal(r.Bytes(), svrRsp)
	// repose parse error
	if err != nil {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("%s Unmarshal error %s", r.String(), err.Error())
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r}, err
	}

	// repose code error
	if svrRsp.Code != 0 {
		subTask["status"] = TaskStatusFail
		subTask["task_resp"] = fmt.Sprintf("svr response error %s", r.String())
		dbtask.SubTaskUpdateAsyncWrite(subTask)
		return job.JobResWithArgs{Args: &ja, Response: r}, err
	}

	// success
	subTask["task_resp"] = r.String()
	dbtask.SubTaskUpdateAsyncWrite(subTask)
	return job.JobResWithArgs{Args: &ja, Response: r}, err
}

// AgentDistribute for quick task.

// AgentDo for quick task.

// Add dbTask info to hb.
func updateConfig(dbTask *AgentTask, hb *AgentHBInfo) {
	for k, v := range dbTask.Data.Config {
		hit := false
		for k1, v1 := range hb.Config {
			if v1.Name == v.Name {
				hit = true
				//delete when all other fields are empty
				if len(dbTask.Data.Config[k].DownloadURL) == 0 && dbTask.Data.Config[k].Version == "" &&
					dbTask.Data.Config[k].SHA256 == "" && dbTask.Data.Config[k].Detail == "" &&
					dbTask.Data.Config[k].Type == "" && dbTask.Data.Config[k].Signature == "" {
					hb.Config = append(hb.Config[:k1], hb.Config[k1+1:]...)
					break
				}

				//update
				if v.DownloadURL != nil && len(v.DownloadURL) != 0 {
					hb.Config[k1].DownloadURL = dbTask.Data.Config[k].DownloadURL
				}
				if v.Version != "" {
					hb.Config[k1].Version = dbTask.Data.Config[k].Version
				}
				if v.SHA256 != "" {
					hb.Config[k1].SHA256 = dbTask.Data.Config[k].SHA256
				}
				if v.Detail != "" {
					hb.Config[k1].Detail = dbTask.Data.Config[k].Detail
				}
				if v.Signature != "" {
					hb.Config[k1].Signature = dbTask.Data.Config[k].Signature
				}
				if v.Type != "" {
					hb.Config[k1].Type = dbTask.Data.Config[k].Type
				}
				break
			}
		}

		//new config item
		if !hit {
			//all is empty
			if len(dbTask.Data.Config[k].DownloadURL) == 0 && dbTask.Data.Config[k].Version == "" &&
				dbTask.Data.Config[k].SHA256 == "" && dbTask.Data.Config[k].Detail == "" &&
				dbTask.Data.Config[k].Type == "" && dbTask.Data.Config[k].Signature == "" {
				continue
			}
			hb.Config = append(hb.Config, dbTask.Data.Config[k])
		}
	}
}
