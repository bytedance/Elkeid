package grpc_handler

import (
	"context"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ProxyHandler struct{}

func (p ProxyHandler) SendHeartbeat(ctx context.Context, request *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	err := client.UpdateProxyHeartbeat(*request)
	if err != nil {
		ylog.Errorf("SendHeartbeat", "ProxyID: %s, ProxyLocalID: %s, Error: %s", request.ProxyID, request.ProxyLocalID, err.Error())
		return nil, status.Errorf(codes.Internal, "Internal Server Error")
	}
	return &pb.HeartbeatResponse{Status: "ok"}, nil
}
