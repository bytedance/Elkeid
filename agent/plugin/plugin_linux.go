package plugin

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bytedance/Elkeid/agent/agent"
	"github.com/bytedance/Elkeid/agent/buffer"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/utils"
	"go.uber.org/zap"
)

func (p *Plugin) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.IsExited() {
		return
	}
	p.Info("plugin is running, will shutdown it")
	p.tx.Close()
	p.rx.Close()
	select {
	case <-time.After(time.Second * 30):
		p.Warn("because of plugin exit's timeout, will kill it")
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
		p.Info("plugin has been killed")
	case <-p.done:
		p.Info("plugin has been shutdown gracefully")
	}
}
func Load(ctx context.Context, config proto.Config) (plg *Plugin, err error) {
	loadedPlg, ok := m.Load(config.Name)
	if ok {
		loadedPlg := loadedPlg.(*Plugin)
		if loadedPlg.Config.Version == config.Version && loadedPlg.cmd.ProcessState == nil {
			err = ErrDuplicatePlugin
			return
		}
		if loadedPlg.Config.Version != config.Version && loadedPlg.cmd.ProcessState == nil {
			loadedPlg.Infof("because of the different plugin's version,the previous version will be shutdown...")
			loadedPlg.Shutdown()
			loadedPlg.Infof("shutdown successfully")
		}
	}
	if config.Signature == "" {
		config.Signature = config.Sha256
	}
	logger := zap.S().With("plugin", config.Name, "pver", config.Version, "psign", config.Signature)
	logger.Info("plugin is loading...")
	workingDirectory := path.Join(agent.WorkingDirectory, "plugin", config.Name)
	// for compatibility
	os.Remove(path.Join(workingDirectory, config.Name+".stderr"))
	os.Remove(path.Join(workingDirectory, config.Name+".stdout"))
	execPath := path.Join(workingDirectory, config.Name)
	err = utils.CheckSignature(execPath, config.Signature)
	if err != nil {
		logger.Warn("check local plugin's signature failed: ", err)
		logger.Info("downloading plugin from remote server...")
		err = utils.Download(ctx, execPath, config)
		if err != nil {
			return
		}
		logger.Info("download done")
	}
	cmd := exec.Command(execPath)
	var rx_r, rx_w, tx_r, tx_w *os.File
	rx_r, rx_w, err = os.Pipe()
	if err != nil {
		return
	}
	tx_r, tx_w, err = os.Pipe()
	if err != nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w)
	cmd.Dir = workingDirectory
	var errFile *os.File
	errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600)
	if err != nil {
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	logger.Info("plugin's process will start")
	err = cmd.Start()
	tx_r.Close()
	rx_w.Close()
	if err != nil {
		return
	}
	plg = &Plugin{
		Config:        config,
		mu:            &sync.Mutex{},
		cmd:           cmd,
		rx:            rx_r,
		updateTime:    time.Now(),
		reader:        bufio.NewReaderSize(rx_r, 1024*128),
		tx:            tx_w,
		done:          make(chan struct{}),
		taskCh:        make(chan proto.Task),
		wg:            &sync.WaitGroup{},
		SugaredLogger: logger,
	}
	plg.wg.Add(3)
	go func() {
		defer plg.wg.Done()
		defer plg.Info("gorountine of waiting plugin's process will exit")
		err = cmd.Wait()
		rx_r.Close()
		tx_w.Close()
		if err != nil {
			plg.Errorf("plugin has exited with error:%v,code:%d", err, cmd.ProcessState.ExitCode())
		} else {
			plg.Infof("plugin has exited with code %d", cmd.ProcessState.ExitCode())
		}
		close(plg.done)
	}()
	go func() {
		defer plg.wg.Done()
		defer plg.Info("gorountine of receiving plugin's data will exit")
		for {
			rec, err := plg.ReceiveData()
			if err != nil {
				if errors.Is(err, bufio.ErrBufferFull) {
					plg.Warn("when receiving data, buffer is full, skip this record")
					continue
				} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
					plg.Error("when receiving data, an error occurred: ", err)
				} else {
					break
				}
			}
			buffer.WriteEncodedRecord(rec)
		}
	}()
	go func() {
		defer plg.wg.Done()
		defer plg.Info("gorountine of sending task to plugin will exit")
		for {
			select {
			case <-plg.done:
				return
			case task := <-plg.taskCh:
				s := task.Size()
				var dst = make([]byte, 4+s)
				_, err = task.MarshalToSizedBuffer(dst[4:])
				if err != nil {
					plg.Errorf("when marshaling a task, an error occurred: %v, ignored this task: %+v", err, task)
					continue
				}
				binary.LittleEndian.PutUint32(dst[:4], uint32(s))
				var n int
				n, err = plg.tx.Write(dst)
				if err != nil {
					if !errors.Is(err, os.ErrClosed) {
						plg.Error("when sending task, an error occurred: ", err)
					}
					return
				}
				atomic.AddUint64(&plg.rxCnt, 1)
				atomic.AddUint64(&plg.rxBytes, uint64(n))
			}
		}
	}()
	m.Store(config.Name, plg)
	return
}
