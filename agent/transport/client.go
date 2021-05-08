package transport

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/agent/global"
	"github.com/bytedance/Elkeid/agent/plugin"
	"github.com/bytedance/Elkeid/agent/transport/connection"

	//
	_ "github.com/bytedance/Elkeid/agent/transport/compressor"
	"go.uber.org/zap"
	grpc "google.golang.org/grpc"
)

var (
	NetMode string
)

func Run() {
	var last time.Time
	for {
		last = time.Now()
		conn, name := connection.New()
		if conn == nil {
			zap.S().Panic("No network is available")
		} else {
			NetMode = name
		}
		ctx, cancel := context.WithCancel(context.Background())
		client, err := global.NewTransferClient(conn).Transfer(ctx, grpc.UseCompressor("snappy"))
		if err != nil {
			zap.S().Panic(err)
		}
		wg := sync.WaitGroup{}
		wg.Add(2)
		go handleReceive(&wg, client)
		go handleSend(&wg, client)
		wg.Wait()
		cancel()
		conn.Close()
		if time.Now().Sub(last) < time.Second*5 {
			zap.S().Panic("Refreshing too often")
		}
	}
}

func handleReceive(wg *sync.WaitGroup, c global.Transfer_TransferClient) {
	defer wg.Done()
	for {
		cmd, err := c.Recv()
		if err != nil {
			zap.S().Error(err)
			return
		}
		s, err := plugin.GetServer()
		if err != nil {
			zap.S().Error(err)
			continue
		}
		if cmd.AgentCtrl == 2 {
			s.Close()
			os.Exit(0)
		}
		zap.S().Info(cmd)
		for _, config := range cmd.Config {
			switch config.Name {
			case "host":
				if config.Version != global.Version {
					err = Download(config.DownloadURL, "elkeid-agent.tmp", config.SHA256)
					if err != nil {
						zap.S().Errorf("Download error:%+v", err)
						continue
					}
					err = os.Rename("elkeid-agent.tmp", "elkeid-agent")
					if err == nil {
						s.Close()
						os.Exit(0)
					} else {
						os.Remove("elkeid-agent")
					}
				}
			default:
				p, ok := s.Get(config.Name)
				if !ok || p.Version() != config.Version {
					wd, err := os.Getwd()
					if err != nil {
						zap.S().Errorf("Get current working directory error:%+v", err)
						continue
					}
					pluginWorkDir := wd + "/plugin/" + config.Name + "/"
					err = os.MkdirAll(pluginWorkDir, 0700)
					if err != nil {
						zap.S().Errorf("Make directory error:%+v", err)
						continue
					}
					err = Download(config.DownloadURL, pluginWorkDir+config.Name, config.SHA256)
					if err != nil {
						zap.S().Errorf("Download error:%+v", err)
						continue
					}
					// Close old plugin
					s.Delete(config.Name)
					new, err := plugin.NewPlugin(config.Name, config.Version, config.SHA256, pluginWorkDir+config.Name)
					if err != nil {
						zap.S().Error(err)
						continue
					}
					s.Insert(config.Name, new)
					if err := new.Run(); err != nil {
						zap.S().Error(err)
						s.Delete(config.Name)
					} else {
						go func(n string) {
							time.Sleep(time.Second * 30)
							if !new.Connected() {
								zap.S().Errorf("Plugin seems to be dead:%v", new)
								s.Delete(n)
							}
						}(config.Name)
					}
				}
			}
		}
		// Compare the currently running plugin list with the issued configuration,
		// and close the plugin that is not in the configuration
		if len(cmd.Config) != 0 {
			plugins := s.PluginList()
			for _, name := range plugins {
				del := true
				for _, config := range cmd.Config {
					if name == config.Name {
						del = false
						break
					}
				}
				if del {
					s.Delete(name)
				}
			}
		}
		if cmd.Task != nil {
			zap.S().Infof("Process task %+v", cmd.Task)
			p, ok := s.Get(cmd.Task.Name)
			if !ok {
				zap.S().Errorf("Plugin not found")
				continue
			}
			preTask := struct {
				Content string `json:"content"`
				ID      uint32 `json:"id"`
			}{}
			err = json.Unmarshal([]byte(cmd.Task.Data), &preTask)
			if err != nil {
				zap.S().Error(err)
				continue
			}
			t := plugin.Task{
				Token:   cmd.Task.Token,
				Content: preTask.Content,
				ID:      preTask.ID,
			}
			err = p.Send(t)
			if err != nil {
				zap.S().Error(err)
				s.Delete(cmd.Task.Name)
			}
		}

	}
}

func handleSend(wg *sync.WaitGroup, c global.Transfer_TransferClient) {
	defer wg.Done()
	buffer := make([]*global.Record, 0, 10000)
	interval := time.NewTicker(time.Millisecond * 100)
	for {
		select {
		// If the channel has data, insert the data into the buffer
		case records := <-global.GrpcChannel:
			{
				buffer = append(buffer, records...)
			}
		// Send data regularly
		case <-interval.C:
			{
				// Buffer is empty, continue to wait
				if len(buffer) == 0 {
					continue
				}
				// Create send request packet
				req := global.RawData{
					IntranetIPv4: global.PrivateIPv4,
					ExtranetIPv4: global.PublicIPv4,
					IntranetIPv6: global.PrivateIPv6,
					ExtranetIPv6: global.PublicIPv6,
					Hostname:     global.Hostname,
					AgentID:      global.AgentID,
					Timestamp:    time.Now().Unix(),
					Version:      global.Version,
					Pkg:          buffer,
				}
				err := c.Send(&req)
				// If you encounter an error when sending, exit directly
				if err != nil {
					zap.S().Error(err)
					return
				}
				// Clear buffer
				buffer = buffer[0:0]
			}
		}
	}
}
