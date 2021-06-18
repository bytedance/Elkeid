package job

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/go-redis/redis/v8"
	"github.com/levigross/grequests"
	"sync"
	"time"
)

type DisJob func(k, v interface{}) (interface{}, error)
type DoJob func(args interface{}) (interface{}, error)
type DoRlt func(k, v interface{}) (interface{}, error)

const (
	jobIdFmt   = "id-%s-%d"
	jobChannel = "chan-%s-%s"
	FinishFlag = "FINISH"

	JobInfo           = "JobInfo:%s"
	JobStat           = "JobStat:%s"
	JobResp           = "JobResp:%s"
	JobRetry          = "JobRetry:%s"
	defaultExpireTime = 60 * 60 * 12
)

const (
	distributeMode = iota
	singleMode
)

type Job interface {
	GetId() string
	Run(chan bool)
	Distribute(k, v interface{}) error
	Retry()
	RltCallback(k, v interface{}) (interface{}, error)
	Finish()
	Stop()
}

type JobResWithArgs struct {
	Args     *JobArgs
	Response *grequests.Response
	Result   string
}

type JobArgs struct {
	Name    string      `json:"name"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Args    interface{} `json:"args"`
	Scheme  string      `json:"scheme"`
	Method  string      `json:"method"`
	Timeout int         `json:"timeout"`
}

type SimpleJob struct {
	Id      string
	Name    string
	Mode    int
	Meta    map[string]interface{}
	Workers []string
	ConNum  int
	Timeout int
	//stop job channel
	Done chan bool
	//
	Dis DisJob
	Do  DoJob
	Rlt DoRlt

	Rds redis.UniversalClient
}

func NewSimpleJob(id string, name string, mode int, meta map[string]interface{}, workers []string, conNum int, timeout int, dis DisJob, do DoJob, rlt DoRlt, rds redis.UniversalClient) SimpleJob {
	var (
		setFlag bool
	)
	ctx := context.Background()
	if id == "" {
		id = fmt.Sprintf(jobIdFmt, name, time.Now().UnixNano())
		setFlag = true
	}
	sj := SimpleJob{
		Id:      id,
		Name:    name,
		Mode:    mode,
		Meta:    meta,
		Workers: workers,
		ConNum:  conNum,
		Timeout: timeout,
		Done:    make(chan bool),
		//callback func
		Dis: dis,
		Do:  do,
		Rlt: rlt,
		Rds: rds,
	}
	if setFlag {
		infoKey := fmt.Sprintf(JobInfo, id)
		sj.Rds.HMSet(ctx, infoKey, map[string]interface{}{
			"id":      id,
			"name":    "name",
			"conNum":  conNum,
			"timeout": timeout,
			"newAt":   time.Now().Unix(),
		})
		sj.Rds.Expire(context.Background(), infoKey, defaultExpireTime*time.Second)
	}
	statKey := fmt.Sprintf(JobStat, id)
	sj.Rds.HSet(ctx, statKey, fmt.Sprintf("%s_new", LocalHost), "ok")
	sj.Rds.Expire(context.Background(), statKey, defaultExpireTime*time.Second)

	return sj
}

func (sj *SimpleJob) GetId() string {
	return sj.Id
}

func (sj *SimpleJob) Distribute(k, v interface{}) error {
	ctx := context.Background()
	ylog.Debugf("SimpleJob", ">>>>[job] %s distribute job", sj.Id)
	//
	statKey := fmt.Sprintf(JobStat, sj.Id)

	jobs, err := sj.Dis(k, v)
	if err != nil {
		ylog.Errorf("SimpleJob", "[job] distribute job error: %s", err.Error())
		sj.Rds.HSet(ctx, statKey, fmt.Sprintf("%s_distribute", LocalHost), "failed")
		return err
	}
	sj.Rds.HSet(ctx, statKey, fmt.Sprintf("%s_distribute", LocalHost), "ok")
	//把任务分发到所有github.com/bytedance/Elkeid/server/manager机器
	hosts := discovery.GetHosts()
	ylog.Debugf("SimpleJob", "[job] distribute hosts: %v", hosts)
	items := jobs.([]JobArgs)
	infoKey := fmt.Sprintf(JobInfo, sj.Id)
	for i, item := range items {
		retries := 10
		jobChannel := fmt.Sprintf(jobChannel, hosts[i%len(hosts)], sj.Id)
		jobBytes, err := json.Marshal(item)
		if err != nil {
			ylog.Errorf("SimpleJob", "[job] marshal error: %s", err.Error())
			sj.Rds.HIncrBy(ctx, infoKey, "distribute_failed_count", 1)
			continue
		}

		//publish
		var intCmd *redis.IntCmd
		for retries >= 0 {
			ylog.Errorf("SimpleJob", ">>>>[job] retry %d publish job %v to channel %s", retries, string(jobBytes), jobChannel)
			intCmd = sj.Rds.Publish(ctx, jobChannel, string(jobBytes))
			if intCmd.Val() == 1 {
				break
			}
			time.Sleep(500 * time.Millisecond)
			retries--
		}

		if intCmd != nil && intCmd.Err() != nil {
			ylog.Errorf("SimpleJob", "[job] publish job error: %v", intCmd.Err().Error())
			sj.Rds.HIncrBy(ctx, infoKey, "distribute_failed_count", 1)
			continue
		}
		sj.Rds.HIncrBy(ctx, infoKey, "distribute_ok_count", 1)
	}
	return nil
}

func (sj *SimpleJob) Finish() {
	hosts := discovery.GetHosts()
	ylog.Debugf("SimpleJob", "[job] finish hosts: %v", hosts)
	for _, host := range hosts {
		jobChannel := fmt.Sprintf(jobChannel, host, sj.Id)
		for i := 0; i < sj.ConNum; i++ {
			//publish
			ylog.Debugf("SimpleJob", ">>>>publish finish to channel %s", jobChannel)
			sj.Rds.Publish(context.Background(), jobChannel, FinishFlag)
		}
		ylog.Debugf("SimpleJob", "[job] finish job %s", sj.Id)
	}
}

func (sj *SimpleJob) Retry() {
	ctx := context.Background()
	retryKey := fmt.Sprintf(JobRetry, sj.Id)
	rLen := int(sj.Rds.LLen(ctx, retryKey).Val())
	hosts := discovery.GetHosts()
	for i := 0; i < rLen; i++ {
		jobData := sj.Rds.RPop(ctx, retryKey).Val()
		jobChannel := fmt.Sprintf(jobChannel, hosts[i%len(hosts)], sj.Id)
		//publish
		ylog.Debugf("SimpleJob", ">>>>[job] publish job %v to channel %s", jobData, jobChannel)
		err := sj.Rds.Publish(ctx, jobChannel, string(jobData)).Err()
		if err != nil {
			ylog.Errorf("SimpleJob", "[job] publish job error: %v", err.Error())
			continue
		}
	}
}

func (sj *SimpleJob) Run(over chan bool) {
	ctx := context.Background()
	//通知manager run over
	defer close(over)

	statKey := fmt.Sprintf(JobStat, sj.Id)
	infoKey := fmt.Sprintf(JobInfo, sj.Id)
	respKey := fmt.Sprintf(JobResp, sj.Id)
	retryKey := fmt.Sprintf(JobRetry, sj.Id)

	defer func() {
		sj.Rds.Expire(ctx, respKey, defaultExpireTime*time.Second)
		sj.Rds.Expire(ctx, retryKey, defaultExpireTime*time.Second)
	}()

	sj.Rds.HSet(ctx, statKey, fmt.Sprintf("%s_run", LocalHost), "ok")

	//订阅任务channel
	jobChannel := fmt.Sprintf(jobChannel, LocalHost, sj.Id)
	ylog.Debugf("SimpleJob", "[job] job sub channel: %s", jobChannel)
	ps := sj.Rds.Subscribe(ctx, jobChannel)
	defer func() {
		_ = ps.Close()
	}()
	_, err := ps.Receive(ctx)
	if err != nil {
		ylog.Errorf("SimpleJob", "[job] pubsub receive error: %s", err.Error())
		return
	}

	ch := ps.Channel()

	wg := &sync.WaitGroup{}
	wg.Add(sj.ConNum)
	//启动多个goroutine处理任务
	for i := 0; i < sj.ConNum; i++ {
		go func(wg *sync.WaitGroup, i int) {
			defer wg.Done()
			ylog.Debugf("SimpleJob", "[job] %s %d goroutine start", sj.Id, i)
			t := time.NewTimer(time.Duration(sj.Timeout) * time.Second)
			defer t.Stop()
			for {
				select {
				case jobMsg := <-ch:
					ylog.Debugf("SimpleJob", "[job] channel %s recv: %s", jobChannel, jobMsg.String())
					if jobMsg.Payload == FinishFlag {
						ylog.Debugf("SimpleJob", "[job] %s %d goroutine finish", sj.Id, i)
						return
					}
					//do job
					rlt, err := sj.Do(jobMsg.Payload)
					if err != nil {
						ylog.Errorf("SimpleJob", "[job] do job error: %s", err.Error())
						sj.Rds.HIncrBy(ctx, infoKey, "do_failed_count", 1)
						sj.Rds.LPush(ctx, retryKey, jobMsg.Payload)
						break
					}
					sj.Rlt(sj.Id, rlt)
					sj.Rds.HIncrBy(ctx, infoKey, "do_ok_count", 1)
					if rwa, ok := rlt.(JobResWithArgs); ok {
						sj.Rds.LPush(ctx, respKey, rwa.Result)
					}

				case <-t.C:
					ylog.Errorf("SimpleJob", "[job] %s goroutine %d run timeout", sj.Id, i)
					return
				case <-sj.Done:
					ylog.Debugf("SimpleJob", "[job] %s groutine %d run done", sj.Id, i)
					return
				}
			}
		}(wg, i)
	}
	wg.Wait()
	ylog.Debugf("SimpleJob", "[job] run %s finish", sj.Id)
	sj.Rds.HSet(ctx, statKey, fmt.Sprintf("%s_finish", LocalHost), "ok")
}

func (sj *SimpleJob) Stop() {
	close(sj.Done)
}

func (sj *SimpleJob) RltCallback(k, v interface{}) (interface{}, error) {
	return sj.Rlt(k, v)
}
