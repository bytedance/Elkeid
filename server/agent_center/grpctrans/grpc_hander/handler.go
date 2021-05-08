package grpc_hander

import (
	"context"
	"errors"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/pool"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"google.golang.org/grpc/peer"
	"time"
)

type TransferHandler struct{}

var (
	//GlobalGRPCPool is the global grpc connection manager
	GlobalGRPCPool *pool.GRPCPool
)

func InitGlobalGRPCPool() {
	option := pool.NewConfig()
	option.PoolLength = common.ConnLimit
	GlobalGRPCPool = pool.NewGRPCPool(option)
}

func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) error {
	//Maximum number of concurrent connections
	if !GlobalGRPCPool.LoadToken() {
		err := errors.New("out of max connection limit")
		ylog.Errorf("Transfer", err.Error())
		return err
	}
	defer func() {
		GlobalGRPCPool.ReleaseToken()
	}()

	//Receive the first packet and get the AgentID
	data, err := stream.Recv()
	if err != nil {
		ylog.Errorf("Transfer", "Transfer error %s", err.Error())
		return err
	}
	agentID := data.AgentID

	//Get the client address
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		ylog.Errorf("Transfer", "Transfer error %s", err.Error())
		return err
	}
	addr := p.Addr.String()
	ylog.Infof("Transfer", ">>>>connection addr: %s", addr)

	//add connection info to the GlobalGRPCPool
	ctx, cancelButton := context.WithCancel(context.Background())
	createAt := time.Now().UnixNano() / (1000 * 1000 * 1000)
	connection := pool.Connection{
		AgentID:     agentID,
		Addr:        addr,
		CreateAt:    createAt,
		CommandChan: make(chan *pool.Command),
		Ctx:         ctx,
		CancelFuc:   cancelButton,
	}
	ylog.Infof("Transfer", ">>>>now set %s %v", agentID, connection)
	err = GlobalGRPCPool.Add(agentID, &connection)
	if err != nil {
		ylog.Errorf("Transfer", "Transfer error %s", err.Error())
		return err
	}
	defer func() {
		ylog.Infof("Transfer", "now delete %s ", agentID)
		GlobalGRPCPool.Delete(agentID)
	}()

	//Process the first of data
	handleRawData(data)

	//Receive data from agent
	go recvData(stream, &connection)
	//Send command to agent
	go sendData(stream, &connection)

	//Every time the agent connects to the server
	//it needs to push the latest configuration to agent
	err = GlobalGRPCPool.PostLatestConfig(agentID)
	if err != nil {
		ylog.Errorf("Transfer", "send config error, %s %s", agentID, err.Error())
	}

	//stop here
	<-connection.Ctx.Done()
	return nil
}

func recvData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
	defer conn.CancelFuc()

	for {
		select {
		case <-conn.Ctx.Done():
			ylog.Errorf("recvData", "the send direction of the tcp is closed, now close the recv direction, %s ", conn.AgentID)
			return
		default:
			data, err := stream.Recv()
			if err != nil {
				ylog.Errorf("recvData", "Transfer Recv Error %s, now close the recv direction of the tcp, %s ", err.Error(), conn.AgentID)
				return
			}
			handleRawData(data)
		}
	}
}

func sendData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
	defer conn.CancelFuc()

	for {
		select {
		case <-conn.Ctx.Done():
			ylog.Infof("sendData", "the recv direction of the tcp is closed, now close the send direction, %s ", conn.AgentID)
			return
		case cmd := <-conn.CommandChan:
			//if cmd is nil, close the connection
			if cmd == nil {
				ylog.Infof("sendData", "get the close signal , now close the send direction of the tcp, %s ", conn.AgentID)
				return
			}
			err := stream.Send(cmd.Command)
			if err != nil {
				ylog.Errorf("sendData", "Send Task Error %s %s ", conn.AgentID, cmd)
				cmd.Error = err
				close(cmd.Ready)
				return
			}
			ylog.Infof("sendData", "Transfer Send %s %s ", conn.AgentID, cmd)
			cmd.Error = nil
			close(cmd.Ready)
		}
	}
}
