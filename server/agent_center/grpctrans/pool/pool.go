package pool

import (
	"context"
	"errors"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"github.com/patrickmn/go-cache"
	"sync"
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

	conf *Config
}

//Connection Info
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
	agentDetail      map[string]interface{} `json:"agent_detail"`
	pluginDetailLock sync.RWMutex
	pluginDetail     map[string]map[string]interface{} `json:"plugin_detail"`
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
	c.agentDetailLock.Lock()
	defer c.agentDetailLock.Unlock()
	c.agentDetail = detail
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

type Command struct {
	Command *pb.Command
	Error   error
	Ready   chan bool
}

//NewGRPCPool create a new GRPCPool.
// -- maxConnTokenCount: Maximum number of concurrent connections
func NewGRPCPool(config *Config) *GRPCPool {
	g := &GRPCPool{
		connPool:  cache.New(-1, -1), //Never expire
		tokenChan: make(chan bool, config.PoolLength),
		confChan:  make(chan string, config.ConfigChanLen),
		taskChan:  make(chan map[string]string, config.TaskChanLen),
		taskList:  make([]map[string]string, 0, config.TaskChanLen),
		conf:      config,
	}

	for i := 0; i < config.PoolLength; i++ {
		g.tokenChan <- true
	}

	go g.checkConfig()
	go g.checkTask()
	return g
}

func (g *GRPCPool) checkConfig() {
	for {
		select {
		case agentID := <-g.confChan:
			config, err := client.GetConfigFromRemote(agentID)
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

//LoadToken
//  Returns true when the current total number of connection < the length of the pool.
func (g *GRPCPool) LoadToken() bool {
	select {
	case _, ok := <-g.tokenChan:
		if ok {
			return true
		}
	default:
	}
	return false
}

//ReleaseToken
// release the connection token to the pool; must be called after the conn is closed.
func (g *GRPCPool) ReleaseToken() {
	g.tokenChan <- true
}

//GetConnectionCount
func (g *GRPCPool) GetCount() int {
	return g.connPool.ItemCount()
}

//GetByAgentID
func (g *GRPCPool) GetByID(agentID string) (*Connection, error) {
	tmp, ok := g.connPool.Get(agentID)
	if !ok {
		return nil, errors.New("agentID not found")
	}
	return tmp.(*Connection), nil
}

//return error if AgentID conflict.
func (g *GRPCPool) Add(agentID string, conn *Connection) error {
	_, ok := g.connPool.Get(agentID)
	if ok {
		return errors.New("agentID conflict")
	}
	g.connPool.Set(agentID, conn, -1)
	return nil
}

//Delete
func (g *GRPCPool) Delete(agentID string) {
	g.connPool.Delete(agentID)
}

//get List
func (g *GRPCPool) GetList() []*Connection {
	connMap := g.connPool.Items()
	res := make([]*Connection, 0)
	for _, v := range connMap {
		conn := v.Object.(*Connection)
		res = append(res, conn)
	}
	return res
}

//Post the latest configuration to agent
func (g *GRPCPool) PostLatestConfig(agentID string) error {
	select {
	case g.confChan <- agentID:
	default:
		return errors.New("confChan is full, please try later")
	}
	return nil
}

//PostCommand
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

//Close send nil conn to close the agent
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

//PushTask2Manager push task to the remote end for reconciliation asynchronously.
func (g *GRPCPool) PushTask2Manager(task map[string]string) error {
	select {
	case g.taskChan <- task:
	default:
		return errors.New("taskChan is full, please try later")
	}
	return nil
}
