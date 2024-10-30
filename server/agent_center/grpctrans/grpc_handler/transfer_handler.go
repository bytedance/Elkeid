package grpc_handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/metrics"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/pool"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/xid"
	"google.golang.org/grpc/peer"
)

type TransferHandler struct{}

var (
	//GlobalGRPCPool is the global grpc connection manager
	GlobalGRPCPool *pool.GRPCPool
)

func InitGlobalGRPCPool() {
	option := pool.NewConfig()
	option.PoolLength = common.ConnLimit
	option.ChanLen = common.ConnLimit * 2
	GlobalGRPCPool = pool.NewGRPCPool(option)

	gauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "elkeid_ac_grpc_conn_count",
		Help: "Elkeid AC grpc connection count",
	}, func() float64 {
		return float64(GlobalGRPCPool.GetCount())
	})
	prometheus.MustRegister(gauge)
}

func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) error {
	//Maximum number of concurrent connections
	if !GlobalGRPCPool.LoadToken() {
		err := errors.New("out of max connection limit")
		ylog.Errorf("Transfer", "LoadToken Error %s", err.Error())
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
		ylog.Errorf("Transfer", "Transfer %s, error: %s", agentID, err.Error())
		return err
	}
	addr := fmt.Sprintf("%s-%s", p.Addr.String(), xid.New().String())
	ylog.Infof("Transfer", ">>>>connection %s, addr: %s", agentID, addr)

	//add connection info to the GlobalGRPCPool
	ctx, cancelButton := context.WithCancel(context.Background())
	createAt := time.Now().UnixNano() / (1000 * 1000 * 1000)
	connection := pool.Connection{
		AgentID:      agentID,
		IntranetIPv4: data.IntranetIPv4,
		IntranetIPv6: data.IntranetIPv6,
		ExtranetIPv4: data.ExtranetIPv4,
		ExtranetIPv6: data.ExtranetIPv6,
		SourceAddr:   addr,
		CreateAt:     createAt,
		CommandChan:  make(chan *pool.Command),
		Ctx:          ctx,
		CancelFuc:    cancelButton,
	}
	connection.Init()
	ylog.Infof("Transfer", ">>>>now set %s %v", agentID, connection)
	err = GlobalGRPCPool.Add(agentID, &connection)
	if err != nil {
		ylog.Errorf("Transfer", "Transfer %s, error: %s", agentID, err.Error())
		return err
	}
	defer func() {
		ylog.Infof("Transfer", "now delete %s ", agentID)
		GlobalGRPCPool.Delete(agentID)

		//删除配置
		if GlobalConfigHandler != nil {
			GlobalConfigHandler.Delete(agentID)
		}

		metrics.ReleaseAgentHeartbeatMetrics(agentID, "agent")
		for _, v := range connection.GetPluginNameList() {
			metrics.ReleaseAgentHeartbeatMetrics(agentID, v)
		}

		if connection.IsNewDriverHeartbeat.CompareAndSwap(true, false) {
			metrics.ReleaseDriverHeartbeat(connection.NewDriverHeartbeatLabels)
		}

		//延迟6秒删除，避免状态被Join覆盖
		time.AfterFunc(time.Second*10, func() {
			ylog.Infof("Evict", "HeartBeatEvict AgentID %s, AgentAddr: %s.", agentID, addr)
			client.HBWriter.Evict(client.HeartBeatEvictModel{
				AgentID:   agentID,
				AgentAddr: addr,
			})
		})
	}()

	//Process the first of data
	handleRawData(data, &connection)

	//Receive data from agent
	go recvData(stream, &connection)
	//Send command to agent
	go sendData(stream, &connection)

	//stop here
	<-connection.Ctx.Done()
	return nil
}

func recvData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
	defer conn.CancelFuc()

	for {
		select {
		case <-conn.Ctx.Done():
			ylog.Warnf("recvData", "the send direction of the tcp is closed, now close the recv direction, %s ", conn.AgentID)
			return
		default:
			data, err := stream.Recv()
			if err != nil {
				ylog.Warnf("recvData", "Transfer Recv Error %s, now close the recv direction of the tcp, %s ", err.Error(), conn.AgentID)
				return
			}
			metrics.RecvCounter.Inc()
			handleRawData(data, conn)
		}
	}
}

func sendData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
	defer conn.CancelFuc()

	for {
		select {
		case <-conn.Ctx.Done():
			ylog.Warnf("sendData", "the recv direction of the tcp is closed, now close the send direction, %s ", conn.AgentID)
			return
		case cmd := <-conn.CommandChan:
			//if cmd is nil, close the connection
			if cmd == nil {
				ylog.Warnf("sendData", "get the close signal , now close the send direction of the tcp, %s ", conn.AgentID)
				return
			}
			err := stream.Send(cmd.Command)
			if err != nil {
				ylog.Errorf("sendData", "Send Task Error %s %v ", conn.AgentID, cmd)
				cmd.Error = err
				close(cmd.Ready)
				return
			}
			metrics.SendCounter.Inc()
			ylog.Infof("sendData", "Transfer Send %s %v ", conn.AgentID, cmd)
			cmd.Error = nil
			close(cmd.Ready)
		}
	}
}
