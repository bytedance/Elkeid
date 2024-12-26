package job

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/go-redis/redis/v8"
	"github.com/levigross/grequests"
)

type DisJob func(jid string, k, v interface{}) (interface{}, error)
type DoJob func(jid string, args interface{}) (interface{}, error)
type DoRlt func(jid string, res interface{}) (interface{}, error)

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

type Job interface {
	GetId() string
	Run(chan bool)
	Distribute(jid string, k, v interface{}) error
	Retry()
	RltCallback(jid string, v interface{}) (interface{}, error)
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
	NeedRes bool //whether save the result to redis
	//stop job channel
	Done chan bool
	//
	Dis DisJob
	Do  DoJob
	Rlt DoRlt

	Rds redis.UniversalClient
}

func NewSimpleJob(id string, name string, mode int, meta map[string]interface{}, workers []string, conNum int, timeout int, needRes bool, dis DisJob, do DoJob, rlt DoRlt, rds redis.UniversalClient) SimpleJob {
	var (
		setFlag bool
	)
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
		NeedRes: needRes,
		Done:    make(chan bool),
		//callback func
		Dis: dis,
		Do:  do,
		Rlt: rlt,
		Rds: rds,
	}
	if setFlag {
		infoKey := fmt.Sprintf(JobInfo, id)
		sj.Rds.HMSet(context.Background(), infoKey, map[string]interface{}{
			"id":      id,
			"name":    "name",
			"conNum":  conNum,
			"timeout": timeout,
			"newAt":   time.Now().Unix(),
		})
		sj.Rds.Expire(context.Background(), infoKey, defaultExpireTime*time.Second)
	}
	statKey := fmt.Sprintf(JobStat, id)
	sj.Rds.HSet(context.Background(), statKey, fmt.Sprintf("%s_new", LocalHost), "ok")
	sj.Rds.Expire(context.Background(), statKey, defaultExpireTime*time.Second)

	return sj
}

func (sj *SimpleJob) GetId() string {
	return sj.Id
}

func (sj *SimpleJob) Distribute(jid string, k, v interface{}) error {
	ylog.Debugf("SimpleJob", ">>>>[job] %s distribute job", sj.Id)
	//
	statKey := fmt.Sprintf(JobStat, sj.Id)

	jobs, err := sj.Dis(sj.Id, k, v)
	if err != nil {
		ylog.Errorf("SimpleJob", "[job] jodID %s,distribute job error: %s", jid, err.Error())
		sj.Rds.HSet(context.Background(), statKey, fmt.Sprintf("%s_distribute", LocalHost), "failed")
		return err
	}

	//把任务分发到所有github.com/bytedance/Elkeid/server/manager机器
	hosts := discovery.GetHosts()
	ylog.Debugf("SimpleJob", "[job] distribute hosts: %v", hosts)
	items := jobs.([]JobArgs)
	infoKey := fmt.Sprintf(JobInfo, sj.Id)
	const retriesMax = 10
	distributeOkCount := 0
	distributeFailedCount := 0
	unDistribute := len(items)
	for i, item := range items {
		unDistribute--
		retries := 0
		jobChannel := fmt.Sprintf(jobChannel, hosts[i%len(hosts)], sj.Id)
		jobBytes, err := json.Marshal(item)
		if err != nil {
			ylog.Errorf("SimpleJob", "[job] marshal error: %s", err.Error())
			distributeFailedCount++
			continue
		}

		//publish
		var intCmd *redis.IntCmd
		for retries < retriesMax {
			intCmd = sj.Rds.Publish(context.Background(), jobChannel, string(jobBytes))
			if intCmd.Val() == 1 {
				break
			}
			time.Sleep(500 * time.Millisecond)
			retries++
			ylog.Debugf("SimpleJob", ">>>>[job] retry %d publish job %v to channel %s", retries, string(jobBytes), jobChannel)
		}

		if intCmd != nil && intCmd.Val() != 1 {
			ylog.Errorf("SimpleJob", ">>>>[job] publish job %v to channel %s failed after all retries!", sj.Id, jobChannel)
			distributeFailedCount++
			continue
		}

		distributeOkCount++
	}

	sj.Rds.HSet(context.Background(), infoKey, "distribute_failed_count", distributeFailedCount)
	sj.Rds.HSet(context.Background(), infoKey, "distribute_ok_count", distributeOkCount)
	sj.Rds.HSet(context.Background(), infoKey, "un_distribute_count", unDistribute)

	sj.Rds.HSet(context.Background(), statKey, fmt.Sprintf("%s_distribute", LocalHost), "ok")
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
	retryKey := fmt.Sprintf(JobRetry, sj.Id)
	rLen := int(sj.Rds.LLen(context.Background(), retryKey).Val())
	hosts := discovery.GetHosts()
	for i := 0; i < rLen; i++ {
		jobData := sj.Rds.RPop(context.Background(), retryKey).Val()
		jobChannel := fmt.Sprintf(jobChannel, hosts[i%len(hosts)], sj.Id)
		//publish
		ylog.Debugf("SimpleJob", ">>>>[job] publish job %v to channel %s", jobData, jobChannel)
		err := sj.Rds.Publish(context.Background(), jobChannel, jobData).Err()
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
		sj.Rds.Expire(context.Background(), respKey, defaultExpireTime*time.Second)
		sj.Rds.Expire(context.Background(), retryKey, defaultExpireTime*time.Second)
	}()

	sj.Rds.HSet(context.Background(), statKey, fmt.Sprintf("%s_run", LocalHost), "ok")

	//订阅任务channel
	jobChannel := fmt.Sprintf(jobChannel, LocalHost, sj.Id)
	ylog.Debugf("SimpleJob", "[job] job sub channel: %s", jobChannel)
	ps := sj.Rds.Subscribe(context.Background(), jobChannel)
	defer func() {
		_ = ps.Close()
	}()
	_, err := ps.Receive(context.Background())
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

			doOKCount := int64(0)
			doFailCount := int64(0)
			resultList := make([]interface{}, 0, 0)
			retryList := make([]interface{}, 0, 0)
			defer func() {
				sj.Rds.HIncrBy(context.Background(), infoKey, "do_ok_count", doOKCount)
				sj.Rds.HIncrBy(context.Background(), infoKey, "do_failed_count", doFailCount)

				if sj.NeedRes {
					sj.push2Redis(ctx, respKey, resultList)
				}

				sj.push2Redis(ctx, retryKey, retryList)
			}()

			for {
				select {
				case jobMsg, ok := <-ch:
					if !ok {
						ylog.Errorf("SimpleJob", "[job] %s goroutine %d chan closed", sj.Id, i)
						return
					}

					ylog.Debugf("SimpleJob", "[job] channel %s recv: %s", jobChannel, jobMsg.String())
					if jobMsg.Payload == FinishFlag {
						ylog.Debugf("SimpleJob", "[job] %s %d goroutine finish", sj.Id, i)
						return
					}
					//do job
					rlt, err := sj.Do(sj.Id, jobMsg.Payload)
					if err != nil {
						ylog.Errorf("SimpleJob", "[job] do job error: %s", err.Error())
						doFailCount++
						retryList = append(retryList, jobMsg.Payload)
					}

					_, _ = sj.Rlt(sj.Id, rlt)

					doOKCount++
					if sj.NeedRes {
						if rwa, ok := rlt.(JobResWithArgs); ok {
							resultList = append(resultList, rwa.Result)
						}
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
	sj.Rds.HSet(context.Background(), statKey, fmt.Sprintf("%s_finish", LocalHost), "ok")
}

func (sj *SimpleJob) Stop() {
	close(sj.Done)
}

func (sj *SimpleJob) RltCallback(k string, v interface{}) (interface{}, error) {
	return sj.Rlt(k, v)
}

func (sj *SimpleJob) push2Redis(ctx context.Context, key string, list []interface{}) {
	//push result
	var gradient = 50
	for i := 0; ; {
		if i+gradient < len(list) {
			err := sj.Rds.LPush(context.Background(), key, list[i:i+gradient]...).Err()
			if err != nil {
				ylog.Errorf("SimpleJob", "[job] %s error %s, key %s len of list %d", sj.Id, err.Error(), key, len(list[i:i+gradient]))
			}
		} else {
			if len(list[i:]) == 0 {
				break
			}

			err := sj.Rds.LPush(context.Background(), key, list[i:]...).Err()
			if err != nil {
				ylog.Errorf("SimpleJob", "[job] %s error %s, key %s len of list %d", sj.Id, err.Error(), key, len(list[i:]))
			}
			break
		}
		i = i + gradient
	}
}
