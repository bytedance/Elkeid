package engine

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"math/rand"
	"sync"
	"time"

	plugins "github.com/bytedance/plugins"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

type Records map[string]map[string]string

func (r Records) Find(key, value string) (string, map[string]string, bool) {
	for k, v := range r {
		if v[key] == value {
			return k, v, true
		}
	}
	return "", map[string]string{}, false
}

type Cache struct {
	// DataType-Key-Record
	m  map[int]Records
	mu *sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		m:  map[int]Records{},
		mu: &sync.RWMutex{},
	}
}

// don't modify returned map
func (c *Cache) Get(dt int, key string) (map[string]string, bool) {
	c.mu.RLock()
	res, ok := c.m[dt][key]
	c.mu.RUnlock()
	return res, ok
}
func (c *Cache) Put(dt int, key string, value map[string]string) {
	c.mu.Lock()
	c.m[dt][key] = value
	c.mu.Unlock()
}
func (c *Cache) clear(dt int) {
	c.mu.Lock()
	c.m[dt] = map[string]map[string]string{}
	c.mu.Unlock()
}

type Handler interface {
	Handle(c *plugins.Client, cache *Cache, seq string)
	Name() string
	DataType() int
}

type handler struct {
	l *zap.SugaredLogger
	Handler
	done     chan struct{}
	interval time.Duration
}

func (h *handler) Handle(c *plugins.Client, cache *Cache) {
	h.l.Info("handling")
	var t struct{}
	select {
	case t = <-h.done:
		f := fnv.New32()
		binary.Write(f, binary.LittleEndian, time.Now().UnixNano())
		seq := hex.EncodeToString(f.Sum(nil))
		h.l.Info("do work")
		cache.clear(h.DataType())
		h.Handler.Handle(c, cache, seq)
	default:
		h.l.Info("wait work")
		t = <-h.done
	}
	h.l.Info("work done")
	h.done <- t
	h.l.Info("handled")
}

type Engine struct {
	m     map[int]*handler
	s     *cron.Cron
	c     *plugins.Client
	cache *Cache
}

func BeforeDawn() time.Duration {
	return -1
}
func (e *Engine) AddHandler(interval time.Duration, h Handler) {
	e.m[h.DataType()] = &handler{
		zap.S().With("name", h.Name()),
		h,
		make(chan struct{}, 1),
		interval,
	}
	e.m[h.DataType()].done <- struct{}{}
}

func (e *Engine) Run() {
	zap.S().Info("engine running")
	for _, h := range e.m {
		go func(h *handler) {
			var spec string
			var r int
			minutes := int(h.interval.Minutes())
			if h.interval == BeforeDawn() {
				spec = fmt.Sprintf("%d %d * * *", rand.Intn(60), rand.Intn(6))
				r = rand.Intn(14400) + 7200
			} else if minutes > 0 {
				r = rand.Intn(minutes * 60)
				spec = fmt.Sprintf("@every %dm", int(minutes))
			} else {
				panic("unknown interval")
			}
			h.l.Infof("init call will after %d secs\n", r)
			time.Sleep(time.Second * time.Duration(r))
			h.l.Info("init call")
			h.Handle(e.c, e.cache)
			time.Sleep(time.Minute * time.Duration(minutes))
			e.s.AddFunc(spec, func() { h.Handle(e.c, e.cache) })
			h.l.Info("add func to scheduler successfully")
		}(h)
	}
	go func() {
		zap.S().Info("scheduler running")
		e.s.Run()
	}()
	// receive task until stop
	for {
		t, err := e.c.ReceiveTask()
		if err != nil {
			break
		}
		zap.S().Infof("received task %+v", t)
		if h, ok := e.m[int(t.DataType)]; ok {
			h.Handle(e.c, e.cache)
			// send result recored
			e.c.SendRecord(
				&plugins.Record{
					DataType:  5100,
					Timestamp: time.Now().Unix(),
					Data: &plugins.Payload{
						Fields: map[string]string{
							"status": "succeed",
							"msg":    "",
							"token":  t.Token,
						},
					}})
		} else {
			// can't find handler
			e.c.SendRecord(
				&plugins.Record{
					DataType:  5100,
					Timestamp: time.Now().Unix(),
					Data: &plugins.Payload{
						Fields: map[string]string{
							"status": "failed",
							"msg":    "the data_type hasn't been implemented",
							"token":  t.Token,
						},
					}})
		}
	}
	zap.S().Warn("engine will stop")
	e.c.Close()
	e.s.Stop()
}

func New(c *plugins.Client, l cron.Logger) *Engine {
	return &Engine{
		map[int]*handler{},
		cron.New(cron.WithChain(cron.SkipIfStillRunning(l)), cron.WithLogger(l)),
		c,
		&Cache{
			m:  map[int]Records{},
			mu: &sync.RWMutex{},
		},
	}
}
