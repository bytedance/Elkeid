package grpc_hander

import (
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/pool"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"strconv"
	"strings"
	"time"
)

func handleRawData(req *pb.RawData) (agentID string) {
	timePkg := fmt.Sprintf("%d", req.Timestamp)
	inIPv4List := strings.Join(req.IntranetIPv4, ",")
	inIPv6List := strings.Join(req.IntranetIPv6, ",")
	exIPv4List := strings.Join(req.ExtranetIPv4, ",")
	exIPv6List := strings.Join(req.ExtranetIPv6, ",")

	for k, v := range req.GetPkg() {
		ylog.Debugf("handleRawData", "[+]key:%v => %v", k, v.GetMessage())

		tmp, ok := v.Message["data_type"]
		if !ok {
			ylog.Errorf("handleRawData", "dataType is not exist, agentID: %s, time: %d ,source data: %v", req.AgentID, req.Timestamp, v.GetMessage())
			continue
		}
		dataType, err := strconv.Atoi(strings.TrimSpace(tmp))
		if err != nil {
			ylog.Errorf("handleRawData", "dataType is not int, data_type: %s , source data: %v", tmp, v.GetMessage())
			continue
		}

		//Add some common field.
		fMessage := req.GetPkg()[k].Message
		fMessage["agent_id"] = req.AgentID
		fMessage["time_pkg"] = timePkg
		fMessage["hostname"] = req.Hostname
		fMessage["version"] = req.Version
		fMessage["in_ipv4_list"] = inIPv4List
		fMessage["in_ipv6_list"] = inIPv6List
		fMessage["ex_ipv4_list"] = exIPv4List
		fMessage["ex_ipv6_list"] = exIPv6List

		switch dataType {
		case 1000:
			//parse the heartbeat data
			parseHeartBeat(fMessage, req)
		case 2000:
			//Task asynchronously pushed to the remote end for reconciliation.
			GlobalGRPCPool.PushTask2Manager(fMessage)
		}

		ylog.Debugf("handleRawData", ">>>parseRawData %#v", fMessage)
		common.KafkaProducer.SendWithKey(req.AgentID, fMessage)
	}
	return req.AgentID
}

func parseHeartBeat(hb map[string]string, req *pb.RawData) {
	agentID := req.AgentID
	conn, err := GlobalGRPCPool.GetByID(agentID)
	if err != nil {
		ylog.Errorf("parseHeartBeat", "parseHeartBeat Error, cannot find the conn of agentID %s\n", agentID)
		return
	}

	clearConn(conn)

	strCPU, ok := hb["cpu"]
	if ok {
		if cpu, err := strconv.ParseFloat(strCPU, 64); err == nil {
			conn.Cpu = cpu
		}
	}

	strIO, ok := hb["io"]
	if ok {
		if io, err := strconv.ParseFloat(strIO, 64); err == nil {
			conn.IO = io
		}
	}

	strMem, ok := hb["memory"]
	if ok {
		if mem, err := strconv.ParseInt(strMem, 10, 64); err == nil {
			conn.Memory = mem
		}
	}

	strSlab, ok := hb["slab"]
	if ok {
		if slab, err := strconv.ParseInt(strSlab, 10, 64); err == nil {
			conn.Slab = slab
		}
	}

	strPlugins, ok := hb["plugins"]
	if ok {
		var plugins []map[string]interface{}
		err = json.Unmarshal([]byte(strPlugins), &plugins)
		if err == nil {
			conn.Plugin = plugins
		}
	}

	conn.NetType = hb["net_type"]
	conn.HostName = req.Hostname
	conn.Version = req.Version
	if req.IntranetIPv4 != nil {
		conn.IntranetIPv4 = req.IntranetIPv4
	}

	if req.ExtranetIPv4 != nil {
		conn.ExtranetIPv4 = req.ExtranetIPv4
	}

	if req.IntranetIPv6 != nil {
		conn.IntranetIPv6 = req.IntranetIPv6
	}

	if req.ExtranetIPv6 != nil {
		conn.ExtranetIPv6 = req.ExtranetIPv6
	}

	//last heartbeat time get from server
	conn.LastHeartBeatTime = time.Now().Unix()
}

func clearConn(conn *pool.Connection) {
	conn.Cpu = 0
	conn.IO = 0
	conn.Memory = 0
	conn.Slab = 0
	conn.LastHeartBeatTime = 0
	conn.Version = ""
	conn.HostName = ""
	conn.NetType = ""
	conn.IntranetIPv4 = make([]string, 0)
	conn.ExtranetIPv4 = make([]string, 0)
	conn.IntranetIPv6 = make([]string, 0)
	conn.ExtranetIPv6 = make([]string, 0)
	conn.Plugin = make([]map[string]interface{}, 0)
}
