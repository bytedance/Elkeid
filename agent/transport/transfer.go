package transport

import (
	"context"
	"encoding/json"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/Elkeid/agent/agent"
	"github.com/bytedance/Elkeid/agent/buffer"
	"github.com/bytedance/Elkeid/agent/host"
	"github.com/bytedance/Elkeid/agent/log"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/transport/connection"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var (
	txCnt      = uint64(0)
	rxCnt      = uint64(0)
	updateTime = time.Now()
)

func GetState(now time.Time) (txTPS, rxTPS float64) {
	instant := now.Sub(updateTime).Seconds()
	if instant != 0 {
		txTPS = float64(atomic.SwapUint64(&txCnt, 0)) / float64(instant)
		rxTPS = float64(atomic.SwapUint64(&rxCnt, 0)) / float64(instant)
	}
	updateTime = now
	return
}

func startTransfer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	retries := 0
	subWg := &sync.WaitGroup{}
	defer subWg.Wait()
	for {
		conn, err := connection.GetConnection(ctx)
		// 如果获取不到conn则启动自保护退出
		if err != nil {
			if retries > 5 {
				zap.S().Error("transfer will shutdown because of no avaliable connections: ", err)
				return
			}
			zap.S().Warnf("wait to get next connection for 5 seconds, current retry times: %v, %v", retries, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 5):
				retries++
				continue
			}
		}
		zap.S().Infof("get connection successfully:idc %v,region %v,netmode %v", connection.IDC.Load(), connection.Region.Load(), connection.NetMode.Load())
		retries = 0
		var client proto.Transfer_TransferClient
		subCtx, cancel := context.WithCancel(ctx)
		client, err = proto.NewTransferClient(conn).Transfer(subCtx, grpc.UseCompressor("snappy"))
		if err == nil {
			subWg.Add(2)
			go handleSend(subCtx, subWg, client)
			go func() {
				// 收到错误后取消服务
				handleReceive(subCtx, subWg, client)
				cancel()
			}()
			subWg.Wait()
		} else {
			zap.S().Error(err)
		}
		cancel()
		zap.S().Info("transfer has been canceled,wait next try to transfer for 5 seconds")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 5):
		}
	}
}

func handleSend(ctx context.Context, wg *sync.WaitGroup, client proto.Transfer_TransferClient) {
	defer wg.Done()
	defer zap.S().Info("send handler will exit")
	// 停止发送数据
	defer client.CloseSend()
	zap.S().Info("send handler running")
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			{
				recs := buffer.ReadEncodedRecords()
				if len(recs) != 0 {
					err := client.Send(&proto.PackagedData{
						Records:      recs,
						AgentId:      agent.ID,
						IntranetIpv4: host.PrivateIPv4.Load().([]string),
						IntranetIpv6: host.PrivateIPv6.Load().([]string),
						ExtranetIpv4: host.PublicIPv4.Load().([]string),
						ExtranetIpv6: host.PublicIPv6.Load().([]string),
						Hostname:     host.Name.Load().(string),
						Version:      agent.Version,
						Product:      agent.Product,
					})
					if err != nil {
						zap.S().Error(err)
					} else {
						atomic.AddUint64(&txCnt, uint64(len(recs)))
					}
					buffer.PutEncodedRecords(recs)
				}
			}
		}
	}
}

func handleReceive(ctx context.Context, wg *sync.WaitGroup, client proto.Transfer_TransferClient) {
	defer wg.Done()
	defer zap.S().Info("receive handler will exit")
	zap.S().Info("receive handler running")
	for {
		cmd, err := client.Recv()
		if err != nil {
			zap.S().Error(err)
			return
		}
		zap.S().Info("received command")
		atomic.AddUint64(&rxCnt, 1)
		if cmd.Task != nil {
			// 给agent的任务
			if cmd.Task.ObjectName == agent.Product {
				switch cmd.Task.DataType {
				case 1050:
					req := UploadRequest{}
					err = json.Unmarshal([]byte(cmd.Task.Data), &req)
					if err != nil {
						log.ErrorWithToken(cmd.Task.Token, err)
					} else {
						req.token = cmd.Task.Token
						err = UploadFile(req)
						if err != nil {
							log.ErrorWithToken(cmd.Task.Token, err)
						}
					}
				//set metadata
				case 1051:
					req := map[string]interface{}{}
					err = json.Unmarshal([]byte(cmd.Task.Data), &req)
					if err != nil {
						zap.S().Errorw("unmarshall data failed: "+err.Error(), "token", cmd.Task.Token)
					} else {
						if idc, ok := req["idc"]; ok {
							if idc, ok := idc.(string); ok {
								out, err := exec.Command(
									agent.Control,
									"set",
									"--idc="+idc).
									CombinedOutput()
								if err != nil {
									log.ErrorWithToken(cmd.Task.Token, "set idc failed: ", string(out), ", "+err.Error())
								} else {
									connection.IDC.Store(idc)
								}
							}
						}
						// high-risk op
						if region, ok := req["region"]; ok {
							if region, ok := region.(string); ok {
								if connection.LookupRegion(region) {
									out, err := exec.Command(
										agent.Control,
										"set",
										"--region="+region).
										CombinedOutput()
									if err != nil {
										log.ErrorWithToken(cmd.Task.Token, "set region failed: ", string(out), ", "+err.Error())
									} else {
										connection.Region.Store(region)
									}
								} else {
									log.ErrorWithToken(cmd.Task.Token, "can't find region: "+region)
								}
							}
						}
					}
				case 1060:
					zap.S().Info("will shutdown agent")
					agent.Cancel()
					zap.S().Info("shutdown agent successfully")
					return
				}
				// 给插件的任务
			} else {
				plg, ok := plugin.Get(cmd.Task.ObjectName)
				if ok {
					err = plg.SendTask(*cmd.Task)
					if err != nil {
						plg.Error("send task to plugin failed: ", err)
					}
				} else {
					zap.S().Error("can't find plugin: ", cmd.Task.ObjectName)
				}
			}
			continue
		}
		// handle cfgs
		cfgs := map[string]*proto.Config{}
		for _, config := range cmd.Configs {
			cfgs[config.Name] = config
		}
		// 升级agent
		if cfg, ok := cfgs[agent.Product]; ok && cfg.Version != agent.Version {
			zap.S().Infof("agent will update:current version %v -> expected version %v", agent.Version, cfg.Version)
			err := agent.Update(*cfg)
			if err == nil {
				zap.S().Info("update successfully")
				agent.Cancel()
				return
			} else {
				zap.S().Error("update failed:", err)
			}
		}
		delete(cfgs, agent.Product)
		// 同步plugin
		err = plugin.Sync(cfgs)
		if err != nil {
			zap.S().Error(err)
		}
		continue

	}
}
