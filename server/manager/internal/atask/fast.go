package atask

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/levigross/grequests"
	"github.com/rs/xid"
	"go.mongodb.org/mongo-driver/bson"
	"time"
)

func getSvrAddr(agentID string) (host string, err error) {
	host, err = infra.Grds.Get(context.Background(), agentID).Result()
	if err != nil {
		ylog.Infof("getSvrAddr", "get server addr of %s from redis error %s", agentID, err.Error())
		collection := infra.MongoClient.Database(infra.MongoDatabase).Collection(infra.AgentHeartBeatCollection)
		var heartbeat AgentHBInfo
		err = collection.FindOne(context.Background(), bson.M{"agent_id": agentID}).Decode(&heartbeat)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s:%d", heartbeat.SourceIp, heartbeat.SourcePort), nil
	}
	return host, err
}

func GenerateToken() string {
	return xid.New().String()
}

func generateTaskID() string {
	return fmt.Sprintf("task-%s", xid.New().String())
}

func sendAgentCommand(agentID string, request *ConfigRequest) (string, interface{}, *grequests.Response, error) {
	body := &AgentQuickTask{AgentID: agentID}
	body.Command = *request

	addr, err := getSvrAddr(agentID)
	if err != nil {
		return "", nil, nil, err
	}

	url := fmt.Sprintf("https://%s/command/", addr)
	option := midware.SvrAuthRequestOption()
	option.JSON = body
	option.RequestTimeout = 5 * time.Second
	r, err := grequests.Post(url, option)
	if err != nil {
		ylog.Errorf("SendQuickTask", "request url %s, body %#v, error %s", url, body, err.Error())
		return url, body, nil, err
	}

	if r.StatusCode != 200 {
		ylog.Errorf("QuickTaskTask", "request url %s, body %#v, code %d, resp %s", url, body, r.StatusCode, r.String())
		return url, body, nil, fmt.Errorf("resp code is %d, resp body is %s", r.StatusCode, r.String())
	}

	rsp := SvrResponse{}
	err = json.Unmarshal(r.Bytes(), &rsp)
	if err != nil {
		ylog.Errorf("QuickTaskTask", "request url %s, body %#v, resp %s, error %s", url, body, r.String(), err.Error())
		return url, body, nil, err
	}

	if rsp.Code != 0 {
		return url, body, nil, fmt.Errorf("%s", rsp.Message)
	}
	return url, body, r, nil
}

// SendFastConfig send new configs to agent.

// SendFastTask send a task to agent and return taskID if needAgentResp is true.
func SendFastTask(agentID string, taskMsg *AgentTaskMsg, needAgentResp bool, timeout int64, appendData map[string]interface{}) (string, error) {
	request := &ConfigRequest{Task: *taskMsg}
	if needAgentResp {
		request.Task.Token = GenerateToken()
	} else {
		request.Task.Token = ""
	}

	url, rBody, resp, err := sendAgentCommand(agentID, request)
	if err != nil {
		return "", err
	}

	if needAgentResp {
		taskID := generateTaskID()
		now := time.Now().Unix()
		//Write the subTask back to db for reconciliation
		tmp := &AgentSubTask{
			TaskType:     TypeAgentTask,
			TaskDataType: taskMsg.DataType,
			TaskData:     rBody,
			AgentID:      agentID,
			Token:        request.Task.Token,
			TaskID:       taskID,
			TaskUrl:      url,
			JobStartTime: now,
			Status:       TaskStatusSuccess,
			UpdateTime:   now,
			InsertTime:   now,
			TaskResult:   "",
			TaskResp:     resp.String(),
			AppendData:   appendData,
		}
		if timeout > 0 {
			tmp.JobTimeOutTime = tmp.JobStartTime + timeout
		}
		dbtask.SubTaskAsyncWrite(tmp)
		return taskID, nil
	}
	return "", nil
}

type TaskResFuc func(subTask *AgentSubTask, err error) error

// SendFastTaskCallBack send a task to agent and call TaskResFuc before return.
