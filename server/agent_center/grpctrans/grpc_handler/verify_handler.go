package grpc_handler

import (
	"context"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VerifyHandler struct{}

func (v VerifyHandler) VerifyInstall(ctx context.Context, request *pb.VerifyInstallRequest) (*pb.VerifyInstallResponse, error) {
	success, accountID, err := client.VerifyInstallKey(*request)
	if err != nil {
		ylog.Errorf("VerifyInstall", "AgentID: %s, Error: %s", request.AgentID, err.Error())
		return nil, status.Errorf(codes.Internal, "Internal Server Error")
	}
	res := pb.VerifyInstallResponse{
		Success:   success,
		AccountID: accountID,
	}
	ylog.Infof("VerifyInstall", "AgentID: %s, VerifyInstall ok, AccountID: %s", request.AgentID, accountID)
	return &res, nil
}
