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
	"github.com/bytedance/Elkeid/agent/core"
	"github.com/bytedance/Elkeid/agent/proto"
	"github.com/bytedance/Elkeid/agent/resource"
	"github.com/bytedance/Elkeid/agent/utils"
	"go.uber.org/zap"
)

var (
	m      = &sync.Map{}
	syncCh = make(chan map[string]*proto.Config, 1)
)

var (
	ErrDuplicatePlugin = errors.New("multiple load the same plugin")
)

type Plugin struct {
	Config proto.Config
	mu     *sync.Mutex
	cmd    *exec.Cmd
	// 从agent视角看待的rx tx
	rx         io.ReadCloser
	updateTime time.Time
	reader     *bufio.Reader
	tx         io.WriteCloser
	taskCh     chan proto.Task
	done       chan struct{}
	wg         *sync.WaitGroup
	// 与上面的rx tx概念相反 是从plugin视角看待的
	rxBytes uint64
	txBytes uint64
	rxCnt   uint64
	txCnt   uint64
	*zap.SugaredLogger
}

type PluginState struct {
	Name string
	resource.ProcInfo
	Version string
	Pid     int
	Exited  bool
	RxSpeed float64
	TxSpeed float64
	RxTPS   float64
	TxTPS   float64
}

func (p *Plugin) GetState(now time.Time) (state PluginState) {
	instant := now.Sub(p.updateTime).Seconds()
	if instant != 0 {
		state.RxSpeed = float64(atomic.SwapUint64(&p.rxBytes, 0)) / float64(instant)
		state.TxSpeed = float64(atomic.SwapUint64(&p.txBytes, 0)) / float64(instant)
		state.RxTPS = float64(atomic.SwapUint64(&p.rxCnt, 0)) / float64(instant)
		state.TxTPS = float64(atomic.SwapUint64(&p.txCnt, 0)) / float64(instant)
	}
	state.Name = p.Config.Name
	state.Version = p.Config.Version
	state.Exited = p.IsExited()
	state.Pid = p.cmd.Process.Pid
	p.updateTime = now
	if !state.Exited {
		var err error
		state.ProcInfo, err = resource.GetProcInfo(state.Pid, now)
		if err != nil {
			zap.S().Error(err)
		}
	}
	return
}

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

func (p *Plugin) IsExited() bool {
	return p.cmd.ProcessState != nil
}

func (p *Plugin) ReceiveData() (rec *proto.EncodedRecord, err error) {
	var length uint32
	var recordBuf []byte
	var lengthBuf []byte
	lengthBuf, err = p.reader.Peek(4)
	if err != nil {
		return
	}
	p.reader.Discard(4)
	length = binary.LittleEndian.Uint32(lengthBuf)
	atomic.AddUint64(&p.txBytes, uint64(length))
	recordBuf, err = p.reader.Peek(int(length))
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			p.reader.Discard(int(length))
		}
		return
	}
	index := 1
	rec = core.RecordPool.Get().(*proto.EncodedRecord)
	var dataType, timestamp int
	var consumed int
	dataType, consumed, err = readVarint(recordBuf[index:])
	if err != nil {
		return
	}
	rec.DataType = int32(dataType)
	index += consumed + 1
	timestamp, consumed, err = readVarint(recordBuf[index:])
	if err != nil {
		return
	}
	rec.Timestamp = int64(timestamp)
	index += consumed + 1
	if index < len(recordBuf) {
		_, consumed, err = readVarint(recordBuf[index:])
		if err != nil {
			return
		}
		index += consumed
		rec.Data = append(rec.Data, recordBuf[index:]...)
	}
	p.reader.Discard(int(length))
	atomic.AddUint64(&p.txCnt, 1)
	return
}

func (p *Plugin) SendTask(task proto.Task) (err error) {
	p.Infof("send task to plugin, data type is %v, token is %v", task.DataType, task.Token)
	select {
	case p.taskCh <- task:
	default:
		err = errors.New("plugin is processing task or context has been cancled")
	}
	return
}

func (p *Plugin) GetWorkingDirectory() string {
	return p.cmd.Dir
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
		reader:        bufio.NewReaderSize(rx_r, 1024*512),
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
			core.Transmission(rec, true)
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

func Get(name string) (*Plugin, bool) {
	plg, ok := m.Load(name)
	if ok {
		return plg.(*Plugin), ok
	}
	return nil, ok
}

func GetAll() (plgs []*Plugin) {
	m.Range(func(key, value interface{}) bool {
		plg := value.(*Plugin)
		plgs = append(plgs, plg)
		return true
	})
	return
}

func Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer zap.S().Info("plugin daemon will exit")
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	zap.S().Info("plugin daemon startup")
	for {
		select {
		case <-ctx.Done():
			zap.S().Info("context has been canceled, will shutdown all plugins")
			subWg := &sync.WaitGroup{}
			m.Range(func(key, value interface{}) bool {
				subWg.Add(1)
				plg := value.(*Plugin)
				go func() {
					defer subWg.Done()
					plg.Shutdown()
					plg.wg.Wait()
				}()
				return true
			})
			subWg.Wait()
			zap.S().Info("shutdown all plugins done")
			m = &sync.Map{}
			return
		case cfgs := <-syncCh:
			zap.S().Infof("syncing plugins...")
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name != agent.Product {
					plg, err := Load(ctx, *cfg)
					// 相同版本的同名插件正在运行，无需操作
					if err == ErrDuplicatePlugin {
						continue
					}
					if err != nil {
						zap.S().Errorf("when load plugin %v:%v, an error occurred: %v", cfg.Name, cfg.Version, err)
					} else {
						plg.Infof("plugin has been loaded")
					}
				}
			}
			// 移除插件
			for _, plg := range GetAll() {
				if _, ok := cfgs[plg.Config.Name]; !ok {
					plg.Infof("when syncing, plugin will be shutdown")
					plg.Shutdown()
					plg.Infof("shutdown successfully")
					m.Delete(plg.Config.Name)
					if err := os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
						plg.Error("delete dir of plugin failed: ", err)
					}
				}
			}
			zap.S().Infof("sync done")
		}
	}
}
