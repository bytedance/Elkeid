package pool

import (
	"context"
	"errors"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"github.com/patrickmn/go-cache"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type GRPCPool struct {
	//connPool is the global agent data Cache.
	//the key is agentID, which use to identify a agent, must be unique.
	//the value is *Connection.
	connPool  *cache.Cache
	tokenChan chan bool

	//confChan is the chan Use to Post the latest configuration to agent.
	confChan chan string

	//taskChan is the chan Use to Post the task to manager, which used for data reconciliation
	taskChan chan map[string]string
	taskList []map[string]string

	//psm and tags
	extraInfoChan  chan string
	extraInfoLock  sync.RWMutex
	extraInfoCache map[string]client.AgentExtraInfo

	conf *Config

	dynamicLimit        int32
	dynamicLimitEndTime int64
}

// Connection Info
type Connection struct {
	Ctx       context.Context    `json:"-"`
	CancelFuc context.CancelFunc `json:"-"`

	//use to post commands to the agent, if the *Command is nil, close the connection.
	//otherwise, send the command to the agent.
	CommandChan chan *Command `json:"-"`

	AgentID    string `json:"agent_id"`
	SourceAddr string `json:"addr"`
	CreateAt   int64  `json:"create_at"`

	agentDetailLock  sync.RWMutex
	agentDetail      map[string]interface{}
	pluginDetailLock sync.RWMutex
	pluginDetail     map[string]map[string]interface{}

	connUpdateStatLock sync.Mutex
	connStatNeedSync   bool //是否需要把状态更新至manager端
}

// Init 初始化同步状态
func (c *Connection) Init() {
	c.connStatNeedSync = false
	go c.connStatWorker()
}

func (c *Connection) GetAgentDetail() map[string]interface{} {
	c.agentDetailLock.RLock()
	defer c.agentDetailLock.RUnlock()
	if c.agentDetail == nil {
		return map[string]interface{}{}
	}
	return c.agentDetail
}

func (c *Connection) SetAgentDetail(detail map[string]interface{}) {
	updated := false
	c.agentDetailLock.Lock()
	defer func() {
		c.agentDetail = detail
		c.agentDetailLock.Unlock()

		if updated {
			c.updateConnStat()
		}
	}()

	if c.agentDetail == nil {
		//新增agent
		updated = true
	} else {
		//check Agent状态是否有变化
		st, okST := c.agentDetail["state"].(string)
		std, okSTD := c.agentDetail["state_detail"].(string)
		s1, ok1 := detail["state"].(string)
		s2, ok2 := detail["state_detail"].(string)
		if ok1 != okST || st != s1 || ok2 != okSTD || s2 != std {
			updated = true
		}

		//异步检测是否有插件离线
		time.AfterFunc(time.Second*10, func() {
			c.pluginDetailLock.Lock()
			defer c.pluginDetailLock.Unlock()
			onlineTime := time.Now().Add(-120 * time.Second).Unix()
			for k := range c.pluginDetail {
				if c.pluginDetail[k]["last_heartbeat_time"].(int64) < onlineTime {
					c.pluginDetail[k]["online"] = false
					c.updateConnStat()
					break
				}
			}
		})
	}
}

func (c *Connection) GetPluginDetail(name string) map[string]interface{} {
	c.pluginDetailLock.Lock()
	defer c.pluginDetailLock.Unlock()
	if c.pluginDetail == nil {
		return map[string]interface{}{}
	}
	return c.pluginDetail[name]
}

func (c *Connection) SetPluginDetail(name string, detail map[string]interface{}) {
	c.pluginDetailLock.Lock()
	defer c.pluginDetailLock.Unlock()
	if c.pluginDetail == nil {
		c.pluginDetail = map[string]map[string]interface{}{}
	}

	//新增插件设置推送到远端
	if _, ok := c.pluginDetail[name]; !ok {
		c.updateConnStat()
	}

	c.pluginDetail[name] = detail
}

func (c *Connection) GetPluginsList() []map[string]interface{} {
	c.pluginDetailLock.Lock()
	defer c.pluginDetailLock.Unlock()
	res := make([]map[string]interface{}, 0, len(c.pluginDetail))
	for k := range c.pluginDetail {
		res = append(res, c.pluginDetail[k])
	}
	return res
}

func (c *Connection) updateConnStat() {
	c.connUpdateStatLock.Lock()
	defer c.connUpdateStatLock.Unlock()

	if !c.connStatNeedSync {
		c.connStatNeedSync = true
	}
}

func (c *Connection) connStatWorker() {
	ylog.Infof("GRPCPool", "%s connStatWorker start!", c.AgentID)
	tk := time.NewTicker(10 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			c.connUpdateStatLock.Lock()
			if c.connStatNeedSync {
				c.connStatNeedSync = false
				c.connUpdateStatLock.Unlock()
				//agent_connection
				client.HBWriter.Join(client.ConnStat{
					AgentInfo:   c.GetAgentDetail(),
					PluginsInfo: c.GetPluginsList(),
				})
			} else {
				c.connUpdateStatLock.Unlock()
			}
		}
	}
}

type Command struct {
	Command *pb.Command
	Error   error
	Ready   chan bool
}

// NewGRPCPool create a new GRPCPool.
// -- maxConnTokenCount: Maximum number of concurrent connections
func NewGRPCPool(config *Config) *GRPCPool {
	g := &GRPCPool{
		connPool:       cache.New(-1, -1), //Never expire
		tokenChan:      make(chan bool, config.PoolLength),
		confChan:       make(chan string, config.ChanLen),
		taskChan:       make(chan map[string]string, config.ChanLen),
		taskList:       make([]map[string]string, 0, config.ChanLen),
		extraInfoChan:  make(chan string, config.ChanLen),
		extraInfoCache: make(map[string]client.AgentExtraInfo),
		conf:           config,
	}

	for i := 0; i < config.PoolLength; i++ {
		g.tokenChan <- true
	}

	go g.checkConfig()
	go g.checkTask()

	//Tags
	go g.loadExtraInfoWorker()
	go g.refreshExtraInfo(config.Interval)
	return g
}

func (g *GRPCPool) checkConfig() {
	for {
		select {
		case agentID := <-g.confChan:
			conn, err := g.GetByID(agentID)
			if err != nil {
				ylog.Errorf("GRPCPool", "GetByID Error %s %s", agentID, err.Error())
				continue
			}

			config, err := client.GetConfigFromRemote(agentID, conn.GetAgentDetail())
			if err != nil {
				ylog.Errorf("GRPCPool", "postConfig Error %s %s", agentID, err.Error())
				continue
			}

			cmd := &pb.Command{
				AgentCtrl: 0,
				Config:    config,
			}
			err = g.PostCommand(agentID, cmd)
			if err != nil {
				ylog.Errorf("GRPCPool", "postConfig Error %s %s", agentID, err)
			}
		}
	}
}

func (g *GRPCPool) checkTask() {
	timer := time.NewTicker(g.conf.TaskTimeWeight)
	for {
		select {
		case task := <-g.taskChan:
			g.taskList = append(g.taskList, task)
		case <-timer.C:
			if len(g.taskList) < 1 {
				continue
			}

			client.PostTask(g.taskList)
			g.taskList = g.taskList[:0]
			continue
		}

		if len(g.taskList) >= g.conf.TaskCountWeight {
			client.PostTask(g.taskList)
			g.taskList = g.taskList[:0]
		}
	}
}

// LoadToken
//
//	Returns true when the current total number of connection < the length of the pool.
func (g *GRPCPool) LoadToken() bool {
	//临时限制
	limit := int(atomic.LoadInt32(&g.dynamicLimit))
	limitTime := atomic.LoadInt64(&g.dynamicLimitEndTime)
	nowCount := g.GetCount()
	if limit >= 0 && time.Now().Unix() < limitTime && nowCount >= limit {
		ylog.Errorf("LoadToken", "hit dynamicLimit %d, lastTime %d, now count %d.", limit, limitTime, nowCount)
		return false
	}

	select {
	case _, ok := <-g.tokenChan:
		if ok {
			return true
		}
	default:
	}
	return false
}

// ReleaseToken
// release the connection token to the pool; must be called after the conn is closed.
func (g *GRPCPool) ReleaseToken() {
	g.tokenChan <- true
}

// GetConnectionCount
func (g *GRPCPool) GetCount() int {
	return g.connPool.ItemCount()
}

// GetByAgentID
func (g *GRPCPool) GetByID(agentID string) (*Connection, error) {
	tmp, ok := g.connPool.Get(agentID)
	if !ok {
		return nil, errors.New("agentID not found")
	}
	return tmp.(*Connection), nil
}

// return error if AgentID conflict.
func (g *GRPCPool) Add(agentID string, conn *Connection) error {
	_, ok := g.connPool.Get(agentID)
	if ok {
		return errors.New("agentID conflict")
	}
	g.connPool.Set(agentID, conn, -1)

	//异步load tag
	select {
	case g.extraInfoChan <- agentID:
	default:
		ylog.Errorf("Add", "newTagsChan is full, agentID %s is skipped, tags will be missing!", agentID)
	}
	return nil
}

// Delete
func (g *GRPCPool) Delete(agentID string) {
	g.connPool.Delete(agentID)
}

// get List
func (g *GRPCPool) GetList() []*Connection {
	connMap := g.connPool.Items()
	res := make([]*Connection, 0)
	for _, v := range connMap {
		conn := v.Object.(*Connection)
		res = append(res, conn)
	}
	return res
}

// Post the latest configuration to agent
func (g *GRPCPool) PostLatestConfig(agentID string) error {
	select {
	case g.confChan <- agentID:
	default:
		return errors.New("confChan is full, please try later")
	}
	return nil
}

// PostCommand
// Post command to agent
func (g *GRPCPool) PostCommand(agentID string, command *pb.Command) (err error) {
	conn, err := g.GetByID(agentID)
	if err != nil {
		return err
	}

	cmdToSend := &Command{
		Command: command,
		Error:   nil,
		Ready:   make(chan bool, 1),
	}
	select {
	case conn.CommandChan <- cmdToSend:
	case <-time.After(g.conf.CommSendTimeOut):
		return errors.New("the sendPool of the agent is full")
	}

	//wait for the result
	select {
	case <-cmdToSend.Ready:
		return cmdToSend.Error
	case <-time.After(g.conf.CommResultTimeOut):
		return errors.New("the command has been sent but get results timed out")
	}
}

// Close send nil conn to close the agent
func (g *GRPCPool) Close(agentID string) (err error) {
	conn, err := g.GetByID(agentID)
	if err != nil {
		return err
	}

	select {
	case conn.CommandChan <- nil:
	case <-time.After(g.conf.CommSendTimeOut):
		return errors.New("the sendPool of the agent is full")
	}
	return nil
}

// PushTask2Manager push task to the remote end for reconciliation asynchronously.
func (g *GRPCPool) PushTask2Manager(task map[string]string) error {
	select {
	case g.taskChan <- task:
	default:
		return errors.New("taskChan is full, please try later")
	}
	return nil
}

func (g *GRPCPool) GetExtraInfoByID(agentID string) *client.AgentExtraInfo {
	g.extraInfoLock.RLock()
	tmp, ok := g.extraInfoCache[agentID]
	g.extraInfoLock.RUnlock()
	if !ok {
		ylog.Debugf("GetExtraInfoByID", "the agentID is not in the connection pool of this server %s", agentID)
		return nil
	}
	return &tmp
}

func (g *GRPCPool) refreshExtraInfo(interval time.Duration) {
	for {
		connMap := g.connPool.Items()
		agentIDList := make([]string, 0)
		for k := range connMap {
			agentIDList = append(agentIDList, k)
		}

		//load from leader
		newCache, err := client.GetExtraInfoFromRemote(agentIDList)
		if err == nil {
			g.extraInfoLock.Lock()
			g.extraInfoCache = newCache
			g.extraInfoLock.Unlock()
		}
		time.Sleep(interval + time.Duration(rand.Intn(30))*time.Second)
	}
}

func (g *GRPCPool) loadExtraInfoWorker() {
	for {
		select {
		case agentID := <-g.extraInfoChan:
			tmp, err := client.GetExtraInfoFromRemote([]string{agentID})
			if err == nil {
				g.extraInfoLock.Lock()
				g.extraInfoCache[agentID] = tmp[agentID]
				g.extraInfoLock.Unlock()
			}
		}
	}
}

func (g *GRPCPool) SetDynamicLimit(val int32, lastSecond int64) {
	atomic.StoreInt32(&g.dynamicLimit, val)
	atomic.StoreInt64(&g.dynamicLimitEndTime, lastSecond+time.Now().Unix())

	time.AfterFunc(time.Duration(lastSecond)*time.Second, func() {
		atomic.StoreInt32(&g.dynamicLimit, -1)
	})
}

func (g *GRPCPool) GetDynamicLimit() (val int32, lastSecond int64) {
	val = atomic.LoadInt32(&g.dynamicLimit)
	if val < 0 {
		return -1, 0
	}
	return val, atomic.LoadInt64(&g.dynamicLimitEndTime) - time.Now().Unix()
}
