package grpc_handler

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/metrics"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/pool"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
)

func handleRawData(req *pb.RawData, conn *pool.Connection) (agentID string) {
	var inIpv4 = strings.Join(req.IntranetIPv4, ",")
	var exIpv4 = strings.Join(req.ExtranetIPv4, ",")
	var inIpv6 = strings.Join(req.IntranetIPv6, ",")
	var exIpv6 = strings.Join(req.ExtranetIPv6, ",")
	var SvrTime = time.Now().Unix()
	var extraInfo = GlobalGRPCPool.GetExtraInfoByID(req.AgentID)

	for k, v := range req.GetData() {
		ylog.Debugf("handleRawData", "Num:%d Timestamp:%d, DataType:%d, AgentID:%s, Hostname:%s", k, v.GetTimestamp(), v.GetDataType(), req.AgentID, req.Hostname)

		mqMsg := &pb.MQData{}
		mqMsg.DataType = req.GetData()[k].DataType
		mqMsg.AgentTime = req.GetData()[k].Timestamp
		mqMsg.Body = req.GetData()[k].Body
		mqMsg.AppendedBody = req.GetData()[k].AppendedBody
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
		mqMsg.AccountID = conn.AccountID
		if extraInfo != nil {
			mqMsg.Tag = extraInfo.Tags
			mqMsg.Enhanced = extraInfo.Enhanced
		} else {
			mqMsg.Tag = ""
			mqMsg.Enhanced = "false"
		}

		metrics.OutputAgentIDCounter.With(prometheus.Labels{"account_id": conn.AccountID, "agent_id": mqMsg.AgentID}).Add(float64(1))

		switch mqMsg.DataType {
		case 900:
			driverLabels, ok := metrics.UpdateFromDriverHeartbeat(mqMsg.AccountID, req.GetAgentID(), req.GetVersion(), req.GetData()[k])
			if ok {
				if conn.IsNewDriverHeartbeat.CompareAndSwap(false, true) {
					conn.NewDriverHeartbeatLabels = driverLabels
				}
				conn.LastNewDriverHeartbeatUpdate = time.Now().Unix()
			}
		case 1000:
			//parse the agent heartbeat data
			detail := parseAgentHeartBeat(req.GetData()[k], req, conn)
			metrics.UpdateFromAgentHeartBeat(conn.AccountID, req.AgentID, "agent", detail)
		case 1001:
			//
			//parse the agent plugins heartbeat data
			detail := parsePluginHeartBeat(req.GetData()[k], req, conn)
			if detail != nil {
				if name, ok := detail["name"].(string); ok {
					metrics.UpdateFromAgentHeartBeat(conn.AccountID, req.AgentID, name, detail)
				}
			}
		case 2001, 2003, 6000, 5100, 5101, 8010, 1021, 1022, 1023, 1024, 1025, 1101, 1031:
			// Asynchronously pushed to the remote end for reconciliation.

			//5100: 主动触发资产数据扫描
			//5101: 组件版本验证
			//8010: 基线扫描
			//1021,1022: 插件启动后首次心跳，插件退出日志
			//1031: 文件主动上传
			//1021-1025: Agent/Plugins status
			//需要发送给manager的数据
			item, err := parseRecord(req.GetData()[k])
			if err != nil {
				continue
			}

			item["data_type"] = fmt.Sprintf("%d", mqMsg.DataType)
			switch mqMsg.DataType {
			case 1021, 1022, 1023, 1024, 1025, 1101, 1031:
				//不包含token的数据
				item["agent_id"] = mqMsg.AgentID
				item["time"] = fmt.Sprintf("%d", mqMsg.AgentTime)
				item["time_pkg"] = fmt.Sprintf("%d", SvrTime)
				item["in_ipv4_list"] = mqMsg.IntranetIPv4
				item["in_ipv6_list"] = mqMsg.IntranetIPv6
				item["ex_ipv4_list"] = mqMsg.ExtranetIPv4
				item["ex_ipv6_list"] = mqMsg.ExtranetIPv6
				item["version"] = mqMsg.Version
				item["hostname"] = mqMsg.Hostname
				item["product"] = mqMsg.Product
				item["token"] = "token" //适配格式
				// plugin start/exit report metrics
				if mqMsg.DataType == 1021 || mqMsg.DataType == 1022 {
					// parse the agent plugins heartbeat data
					detail := parsePluginHeartBeat(req.GetData()[k], req, conn)
					if detail != nil {
						//todo del log
						ylog.Infof("handleRawData", "agentID:%s, detail:%#v", mqMsg.AgentID, detail)
					}
				}
			default:
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
			ylog.Infof("AgentErrorLog", "AgentID %s, Timestamp %d, DataType %d, Body %s", req.AgentID, req.GetData()[k].Timestamp, req.GetData()[k].DataType, string(b))
		}

		common.KafkaProducer.SendPBWithKey(req.AgentID, mqMsg)
	}
	return req.AgentID
}

func parseAgentHeartBeat(record *pb.Record, req *pb.RawData, conn *pool.Connection) map[string]interface{} {
	hb, err := parseRecord(record)
	if err != nil {
		return nil
	}

	//强制校验心跳字段
	detail := make(map[string]interface{}, len(hb)+9)
	for k, v := range hb {
		//必须为string
		if common.Contains(common.StringHBFields, k) {
			detail[k] = v
			continue
		}
		//必须为float
		if common.Contains(common.FloatHBFields, k) {
			fv, err := strconv.ParseFloat(v, 64)
			if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
				detail[k] = 0
			} else {
				detail[k] = fv
			}
			continue
		}

		//其他字段
		fv, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
			detail[k] = v
		} else {
			detail[k] = fv
		}
	}

	if req.AccountID != "" {
		detail["account_id"] = req.AccountID
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
	detail["online"] = true
	detail["last_heartbeat_time"] = time.Now().Unix()

	detail["source_ip"] = common.LocalIP
	detail["source_ipv4"] = common.LocalIP
	detail["source_ipv6"] = ""
	detail["source_port"] = common.HttpPort

	os, ok1 := detail["os"].(string)
	info, ok2 := detail["plugins_brief_info"].(string)
	if !ok1 || !ok2 {
		ylog.Errorf("parseAgentHeartBeat", "plugins_brief_info/os is not exists")
	} else {
		//oldInfo, _ := conn.GetAgentDetail()["plugins_brief_info"].(string)
		//if info != oldInfo {
		//	//如果插件信息不一致则重新生成字段
		//	status, list, err := parseBriefPluginsInfo(info, os)
		//	if err != nil {
		//		ylog.Errorf("parseAgentHeartBeat", "parseBriefPluginsInfo error %s", err.Error())
		//	} else {
		//		detail["plugins_status"] = status
		//		detail["abnormal_plugins_list"] = list
		//	}
		//}

		status, list, err := parseBriefPluginsInfo(info, os)
		if err != nil {
			ylog.Errorf("parseAgentHeartBeat", "parseBriefPluginsInfo error %s", err.Error())
		} else {
			detail["plugins_status"] = status
			detail["abnormal_plugins_list"] = list
		}
	}

	if len(conn.GetAgentDetail()) == 0 {
		conn.SetAgentDetail(detail)

		//延迟30秒，确保首次心跳已经写入manager
		time.AfterFunc(time.Second*30, func() {
			//Every time the agent connects to the server
			//it needs to push the latest configuration to agent
			err = GlobalGRPCPool.PostLatestConfig(req.AgentID)
			if err != nil {
				ylog.Errorf("Transfer", "send config error, %s %s", req.AgentID, err.Error())
			}
		})
	} else {
		conn.SetAgentDetail(detail)
	}

	return detail
}

func parseBriefPluginsInfo(briefInfo string, os string) (status, abnormalInfo string, err error) {
	info := make([]common.PluginsInfo, 0, 5)
	tmp := make(map[string]bool, 5)
	abnormalList := make([]string, 0, 5)

	err = json.Unmarshal([]byte(briefInfo), &info)
	if err != nil {
		return "", "", err
	}

	if os == "linux" {
		for _, v := range info {
			if v.Status != "running" {
				continue
			}
			if _, ok := common.LinuxPluginsList[v.Name]; ok {
				tmp[v.Name] = true
			}
		}
		if len(tmp) >= len(common.LinuxPluginsList) {
			return common.PluginsStatusAllOnline, "", nil
		} else if len(tmp) == 0 {
			for k := range common.LinuxPluginsList {
				abnormalList = append(abnormalList, k)
			}
			return common.PluginsStatusAllOffline, strings.Join(abnormalList, ","), nil
		} else {
			//找到未开启插件
			for k := range common.LinuxPluginsList {
				if _, ok := tmp[k]; !ok {
					abnormalList = append(abnormalList, k)
				}
			}
			return common.PluginsStatusAllSomeOnline, strings.Join(abnormalList, ","), nil
		}
	} else {
		for _, v := range info {
			if v.Status != "running" {
				continue
			}
			if _, ok := common.WindowsPluginsList[v.Name]; ok {
				tmp[v.Name] = true
			}
		}
		if len(tmp) >= len(common.WindowsPluginsList) {
			return common.PluginsStatusAllOnline, "", nil
		} else if len(tmp) == 0 {
			for k := range common.WindowsPluginsList {
				abnormalList = append(abnormalList, k)
			}
			return common.PluginsStatusAllOffline, strings.Join(abnormalList, ","), nil
		} else {
			//找到未开启插件
			for k := range common.WindowsPluginsList {
				if _, ok := tmp[k]; !ok {
					abnormalList = append(abnormalList, k)
				}
			}
			return common.PluginsStatusAllSomeOnline, strings.Join(abnormalList, ","), nil
		}
	}
}

func parsePluginHeartBeat(record *pb.Record, req *pb.RawData, conn *pool.Connection) map[string]interface{} {
	data, err := parseRecord(record)
	if err != nil {
		return nil
	}

	pluginName, ok := data["name"]
	if !ok {
		ylog.Errorf("parsePluginHeartBeat", "parsePluginHeartBeat Error, cannot find the name of plugin data %v", data)
		return nil
	}

	detail := make(map[string]interface{}, len(data)+8)
	for k, v := range data {
		//部分字段不需要修改
		if k == "pversion" {
			detail[k] = v
			continue
		}

		fv, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
			detail[k] = v
		} else {
			detail[k] = fv
		}
	}
	//last heartbeat time get from server
	detail["last_heartbeat_time"] = time.Now().Unix()
	detail["online"] = true
	if req.AccountID != "" {
		detail["account_id"] = req.AccountID
	}

	conn.SetPluginDetail(pluginName, detail)
	return detail
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
