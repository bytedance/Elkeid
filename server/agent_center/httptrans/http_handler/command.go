package http_handler

import (
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/grpc_handler"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/gin-gonic/gin"
)

type CommandRequest struct {
	AgentID string        `json:"agent_id" bson:"agent_id" binding:"required"`
	Command CommandDetail `json:"command" bson:"command" binding:"required"`
}

type CommandDetail struct {
	AgentCtrl int32       `json:"agent_ctrl,omitempty"`
	Task      *TaskMsg    `json:"task,omitempty"`
	Config    []ConfigMsg `json:"config,omitempty"`
}

type TaskMsg struct {
	DataType int32  `json:"data_type,omitempty"`
	Name     string `json:"name,omitempty"`
	Data     string `json:"data,omitempty"`
	Token    string `json:"token,omitempty"`
}

type ConfigMsg struct {
	Name        string   `json:"name,omitempty"`
	Type        string   `json:"type,omitempty"`
	Version     string   `json:"version,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	Signature   string   `json:"signature,omitempty"`
	DownloadURL []string `json:"download_url,omitempty"`
	Detail      string   `json:"detail,omitempty"`
}

func PostCommand(c *gin.Context) {
	var taskModel CommandRequest
	err := c.BindJSON(&taskModel)
	if err != nil {
		CreateResponse(c, ParamInvalidErrorCode, err.Error())
		ylog.Errorf("PostCommand", ">>>>ConnReset Parse para error : %s", err.Error())
		return
	}

	mgCommand := &pb.Command{
		AgentCtrl: taskModel.Command.AgentCtrl,
	}

	if taskModel.Command.Config != nil {
		mgCommand.Config = make([]*pb.ConfigItem, 0, len(taskModel.Command.Config))
		for _, v := range taskModel.Command.Config {
			tmp := &pb.ConfigItem{
				Name:        v.Name,
				Version:     v.Version,
				DownloadURL: v.DownloadURL,
				SHA256:      v.SHA256,
				Detail:      v.Detail,
				Type:        v.Type,
				Signature:   v.Signature,
			}
			mgCommand.Config = append(mgCommand.Config, tmp)
		}
	}

	if taskModel.Command.Task != nil {
		task := pb.PluginTask{
			Name:     taskModel.Command.Task.Name,
			DataType: taskModel.Command.Task.DataType,
			Data:     taskModel.Command.Task.Data,
			Token:    taskModel.Command.Task.Token,
		}
		mgCommand.Task = &task
	}

	err = grpc_handler.GlobalGRPCPool.PostCommand(taskModel.AgentID, mgCommand)
	if err != nil {
		CreateResponse(c, UnknownErrorCode, err.Error())
		ylog.Errorf("PostCommand", "error : %s, agentid: %s", err.Error(), taskModel.AgentID)
		return
	}
	CreateResponse(c, SuccessCode, "")
	return
}
