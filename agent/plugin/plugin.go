package plugin

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/Elkeid/agent/agent"
	"github.com/bytedance/Elkeid/agent/buffer"
	"github.com/bytedance/Elkeid/agent/proto"
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

func (p *Plugin) GetState() (RxSpeed, TxSpeed, RxTPS, TxTPS float64) {
	now := time.Now()
	instant := now.Sub(p.updateTime).Seconds()
	if instant != 0 {
		RxSpeed = float64(atomic.SwapUint64(&p.rxBytes, 0)) / float64(instant)
		TxSpeed = float64(atomic.SwapUint64(&p.txBytes, 0)) / float64(instant)
		RxTPS = float64(atomic.SwapUint64(&p.rxCnt, 0)) / float64(instant)
		TxTPS = float64(atomic.SwapUint64(&p.txCnt, 0)) / float64(instant)
	}
	p.updateTime = now
	return
}
func (p *Plugin) Name() string {
	return p.Config.Name
}
func (p *Plugin) Version() string { return p.Config.Version }
func (p *Plugin) Pid() int {
	return p.cmd.Process.Pid
}
func (p *Plugin) IsExited() bool {
	return p.cmd.ProcessState != nil
}

func (p *Plugin) ReceiveData() (rec *proto.EncodedRecord, err error) {
	var l uint32
	err = binary.Read(p.reader, binary.LittleEndian, &l)
	if err != nil {
		return
	}
	_, err = p.reader.Discard(1)
	if err != nil {
		return
	}
	te := 1

	rec = buffer.GetEncodedRecord()
	var dt, ts, e int

	dt, e, err = readVarint(p.reader)
	if err != nil {
		return
	}
	_, err = p.reader.Discard(1)
	if err != nil {
		return
	}
	te += e + 1
	rec.DataType = int32(dt)

	ts, e, err = readVarint(p.reader)
	if err != nil {
		return
	}
	_, err = p.reader.Discard(1)
	if err != nil {
		return
	}
	te += e + 1
	rec.Timestamp = int64(ts)

	if uint32(te) < l {
		_, e, err = readVarint(p.reader)
		if err != nil {
			return
		}
		te += e
		ne := int(l) - te
		if cap(rec.Data) < ne {
			rec.Data = make([]byte, ne)
		} else {
			rec.Data = rec.Data[:ne]
		}
		_, err = io.ReadFull(p.reader, rec.Data)
		if err != nil {
			return
		}
	}
	atomic.AddUint64(&p.txCnt, 1)
	atomic.AddUint64(&p.txBytes, uint64(l))
	return
}

func (p *Plugin) SendTask(task proto.Task) (err error) {
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
