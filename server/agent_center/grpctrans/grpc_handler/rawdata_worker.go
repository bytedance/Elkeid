package grpc_handler

import (
	"encoding/json"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/kafka"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/pool"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/gogo/protobuf/proto"
	"strconv"
	"strings"
	"time"
)

func handleRawData(req *pb.RawData, conn *pool.Connection) (agentID string) {
	var inIpv4 = strings.Join(req.IntranetIPv4, ",")
	var exIpv4 = strings.Join(req.ExtranetIPv4, ",")
	var inIpv6 = strings.Join(req.IntranetIPv6, ",")
	var exIpv6 = strings.Join(req.ExtranetIPv6, ",")
	var SvrTime = time.Now().Unix()
	var extraInfo = GlobalGRPCPool.GetExtraInfoByID(req.AgentID)

	for k, v := range req.GetData() {
		ylog.Debugf("handleRawData", "Timestamp:%d, DataType:%d, AgentID:%s, Hostname:%s", k, v.GetTimestamp(), v.GetDataType(), req.AgentID, req.Hostname)

		//Loading from the object pool, which can improve performance
		mqMsg := kafka.MQMsgPool.Get().(*pb.MQData)
		mqMsg.DataType = req.GetData()[k].DataType
		mqMsg.AgentTime = req.GetData()[k].Timestamp
		mqMsg.Body = req.GetData()[k].Body
		mqMsg.AgentID = req.AgentID
		mqMsg.IntranetIPv4 = inIpv4
		mqMsg.ExtranetIPv4 = exIpv4
		mqMsg.IntranetIPv6 = inIpv6
		mqMsg.ExtranetIPv6 = exIpv6
		mqMsg.Hostname = req.Hostname
		mqMsg.Version = req.Version
		mqMsg.Product = req.Product
		mqMsg.SvrTime = SvrTime
		mqMsg.PSMName = ""
		mqMsg.PSMPath = ""
		if extraInfo != nil {
			mqMsg.Tag = extraInfo.Tags
		} else {
			mqMsg.Tag = ""
		}

		switch mqMsg.DataType {
		case 1000:
			//parse the agent heartbeat data
			parseAgentHeartBeat(req.GetData()[k], req, conn)
		case 1001:
			//
			//parse the agent plugins heartbeat data
			parsePluginHeartBeat(req.GetData()[k], req, conn)
		case 2001, 2003, 6003:
			//Task asynchronously pushed to the remote end for reconciliation.
			item, err := parseRecord(req.GetData()[k])
			if err != nil {
				continue
			}

			err = GlobalGRPCPool.PushTask2Manager(item)
			if err != nil {
				ylog.Errorf("handleRawData", "PushTask2Manager error %s", err.Error())
			}
		case 1010, 1011:
			//agent or plugin error log
			item, err := parseRecord(req.GetData()[k])
			if err != nil {
				continue
			}
			b, err := json.Marshal(item)
			if err != nil {
				continue
			}
			ylog.Infof("AgentErrorLog", "%s", string(b))
		}

		common.KafkaProducer.SendPBWithKey(req.AgentID, mqMsg)
	}
	return req.AgentID
}

func parseAgentHeartBeat(record *pb.Record, req *pb.RawData, conn *pool.Connection) {
	var fv float64
	hb, err := parseRecord(record)
	if err != nil {
		return
	}

	//存储心跳数据到connect
	detail := make(map[string]interface{}, len(hb)+9)
	for k, v := range hb {
		//部分字段不需要修改
		if k == "platform_version" {
			detail[k] = v
			continue
		}

		fv, err = strconv.ParseFloat(v, 64)
		if err == nil {
			detail[k] = fv
		} else {
			detail[k] = v
		}
	}
	detail["agent_id"] = req.AgentID
	detail["agent_addr"] = conn.SourceAddr
	detail["create_at"] = conn.CreateAt
	if req.IntranetIPv4 != nil {
		detail["intranet_ipv4"] = req.IntranetIPv4
	} else {
		detail["intranet_ipv4"] = []string{}
	}
	if req.ExtranetIPv4 != nil {
		detail["extranet_ipv4"] = req.ExtranetIPv4
	} else {
		detail["extranet_ipv4"] = []string{}
	}
	if req.IntranetIPv6 != nil {
		detail["intranet_ipv6"] = req.IntranetIPv6
	} else {
		detail["intranet_ipv6"] = []string{}
	}
	if req.ExtranetIPv6 != nil {
		detail["extranet_ipv6"] = req.ExtranetIPv6
	} else {
		detail["extranet_ipv6"] = []string{}
	}
	detail["version"] = req.Version
	detail["hostname"] = req.Hostname
	detail["product"] = req.Product

	//last heartbeat time get from server
	detail["last_heartbeat_time"] = time.Now().Unix()
	conn.SetAgentDetail(detail)
}

func parsePluginHeartBeat(record *pb.Record, req *pb.RawData, conn *pool.Connection) {
	var fv float64

	data, err := parseRecord(record)
	if err != nil {
		return
	}

	pluginName, ok := data["name"]
	if !ok {
		ylog.Errorf("parsePluginHeartBeat", "parsePluginHeartBeat Error, cannot find the name of plugin data %v", data)
		return
	}

	detail := make(map[string]interface{}, len(data)+8)
	for k, v := range data {
		//部分字段不需要修改
		if k == "pversion" {
			detail[k] = v
			continue
		}

		fv, err = strconv.ParseFloat(v, 64)
		if err == nil {
			detail[k] = fv
		} else {
			detail[k] = v
		}

	}
	//last heartbeat time get from server
	detail["last_heartbeat_time"] = time.Now().Unix()

	conn.SetPluginDetail(pluginName, detail)
}

func parseRecord(hb *pb.Record) (map[string]string, error) {
	item := new(pb.Item)
	err := proto.Unmarshal(hb.Body, item)
	if err != nil {
		ylog.Errorf("parseRecord", "parseRecord Error %s", err.Error())
		return nil, err
	}
	return item.Fields, nil
}
