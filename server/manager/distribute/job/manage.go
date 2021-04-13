package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/manger/biz/midware"
	"github.com/bytedance/Elkeid/server/manger/infra"
	"github.com/bytedance/Elkeid/server/manger/infra/discovery"
	"github.com/bytedance/Elkeid/server/manger/infra/ylog"
	"github.com/levigross/grequests"
	"sync"
	"time"
)

const (
	defaultCheckInterval    = 30
	defaultNewJobChannelLen = 1024

	newAction    = "new"
	stopAction   = "stop"
	finishAction = "finish"

	syncURL = "http://%s/api/v0/inner/sync"
)

var (
	JM *jobManager
	CM *cronJobManager
)

func init() {
	ylog.Infof("JOB_MANAGE", "job manage init")
	JM = newJobManager()
	//cron job init
	CM = NewCronJobManager()
	CM.add("Server_AgentStat", 10, 1, 120)
	CM.add("Server_AgentList", 10, 2, 20)
}

//cron job manage
const (
	cronLock = "LOCK:%s:%d"
)

type cronJob struct {
	name     string
	interval int
	conNum   int
	timeout  int
}

type cronJobManager struct {
	mu   sync.Mutex
	jobs []cronJob
	done chan bool
}

func NewCronJobManager() *cronJobManager {
	cj := &cronJobManager{
		jobs: make([]cronJob, 0),
		done: make(chan bool),
	}
	go cj.manage()
	return cj
}

func (cm *cronJobManager) add(name string, interval int, conNum int, timeout int) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.jobs = append(cm.jobs, cronJob{name: name, interval: interval, conNum: conNum, timeout: timeout})
}

func (cm *cronJobManager) manage() {
	ctx := context.Background()
	ylog.Debugf("cronJobManager", "cron jobs: %v", cm.jobs)
	for _, cj := range cm.jobs {
		go func(cj cronJob) {
			t := time.NewTicker(time.Duration(cj.interval) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					lock := fmt.Sprintf(cronLock, cj.name, time.Now().Unix()/int64(cj.interval))
					ok := infra.Grds.SetNX(ctx, lock, 1, time.Duration(cj.interval)*time.Second).Val()
					ylog.Debugf("cronJobManager", "set lock %s %v", lock, ok)
					if !ok {
						break
					}
					jobId, err := NewJob(cj.name, cj.conNum, cj.timeout)
					if err != nil {
						ylog.Debugf("cronJobManager", "[cronJobManager] new job error: %s", err.Error())
						break
					}
					ylog.Debugf("cronJobManager", "[cronJobManager] new job: %s", jobId)
					DistributeJob(jobId, cj.name, nil)
					Finish(jobId)
				case <-cm.done:
					return
				}
			}
		}(cj)
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			//fmt.Printf("cron jobs: %v\n", cm.jobs)
		case <-cm.done:
			return
		}
	}
}

func (cm *cronJobManager) stop() {
	close(cm.done)
}

// job manage

type NewSyncInfo struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	ConNum  int    `json:"con_num"`
	Timeout int    `json:"timeout"`
}

type StopSyncInfo struct {
	Id string `json:"id"`
}

type FinishSyncInfo struct {
	Id string `json:"id"`
}

type TransInfo struct {
	Action string `json:"action"`
	Data   string `json:"data"`
}

type runner struct {
	name string
	job  Job
	over chan bool
}

type jobManager struct {
	mu sync.Mutex

	runningMap     map[string]*runner
	runningChannel chan *runner

	over chan bool
}

func newJobManager() *jobManager {
	jm := &jobManager{
		runningMap:     make(map[string]*runner),
		runningChannel: make(chan *runner, defaultNewJobChannelLen),
		over:           make(chan bool),
	}
	go jm.manage()

	return jm
}

func (jm *jobManager) manage() {
	dt := time.NewTicker(defaultCheckInterval * time.Second)
	defer dt.Stop()

	for {
		select {
		case r := <-jm.runningChannel:
			ylog.Debugf("jobManager", "[manager] new job: %s", r.name)
			job := r.job
			over := r.over
			go job.Run(over)
			jm.runningMap[job.GetId()] = r
			//监控结束
			go func(r *runner) {
				select {
				case <-r.over:
					ylog.Debugf("jobManager", "[manager] job %s informed finish", r.job.GetId())
					jm.mu.Lock()
					delete(jm.runningMap, r.job.GetId())
					jm.mu.Unlock()
					return
				}
			}(r)
		case <-dt.C:
			jm.mu.Lock()
			ylog.Debugf("jobManager", "[manager] running job: %v", jm.runningMap)
			jm.mu.Unlock()
		case <-jm.over:
			ylog.Debugf("jobManager", "[manager] run over")
			return
		}
	}
}

func (jm *jobManager) newJob(name string, conNum int, timeout int) (Job, error) {
	job := NewApiJob("", name, conNum, timeout, infra.Grds)
	if job == nil {
		return nil, errors.New("new job failed")
	}
	over := make(chan bool)
	select {
	case jm.runningChannel <- &runner{name: name, job: job, over: over}:
		//fmt.Printf("[manager] new a job\n")
	default:
		ylog.Errorf("jobManager", "[manager] new a job, running channel is block")
		return nil, errors.New("running channel is block")
	}
	//sync
	newInfo := NewSyncInfo{
		Id:      job.GetId(),
		Name:    name,
		ConNum:  conNum,
		Timeout: timeout,
	}
	data, _ := json.Marshal(newInfo)
	transInfo := TransInfo{
		Action: newAction,
		Data:   string(data),
	}
	//sync send
	jm.syncSend(transInfo)
	return job, nil
}

func (jm *jobManager) syncSend(transInfo TransInfo) {
	othHosts := discovery.GetOtherHosts()
	option := midware.InnerAuthRequestOption()
	option.JSON = transInfo
	option.RequestTimeout = 2 * time.Second
	for _, host := range othHosts {
		url := fmt.Sprintf(syncURL, host)
		_, err := grequests.Post(url, option)
		if err != nil {
			ylog.Errorf("jobManager", "sync send to %s error: %s", host, err.Error())
			continue
		}
		ylog.Debugf("jobManager", "sync send to %s %v ok", host, transInfo)
	}
}

func (jm *jobManager) syncRecv(transInfo TransInfo) {
	ylog.Debugf("jobManager", "[manage] sync recv: %v", transInfo)
	switch transInfo.Action {
	case newAction:
		newInfo := NewSyncInfo{}
		if err := json.Unmarshal([]byte(transInfo.Data), &newInfo); err != nil {
			ylog.Errorf("jobManager", "json unmarshal error: %s", err.Error())
			return
		}
		job := NewApiJob(newInfo.Id, newInfo.Name, newInfo.ConNum, newInfo.Timeout, infra.Grds)
		if job == nil {
			return
		}
		over := make(chan bool)
		select {
		case jm.runningChannel <- &runner{name: newInfo.Name, job: job, over: over}:
			ylog.Debugf("jobManager", "[manager] new a job: %s", newInfo.Id)
		default:
			ylog.Errorf("jobManager", "[manager] new a job, running channel is block")
		}
	case stopAction:
		stopInfo := StopSyncInfo{}
		if err := json.Unmarshal([]byte(transInfo.Data), &stopInfo); err != nil {
			ylog.Errorf("jobManager", "[manager] json unmarshal error: %s", err.Error())
			return
		}
		jm.mu.Lock()
		if runner, ok := jm.runningMap[stopInfo.Id]; ok {
			runner.job.Stop()
		}
		jm.mu.Unlock()
	default:
		ylog.Infof("jobManager", "[manager] action not support")
	}
}

func (jm *jobManager) stopJob(jobId string) {
	jm.mu.Lock()
	if runner, ok := jm.runningMap[jobId]; ok {
		runner.job.Stop()
	}
	jm.mu.Unlock()
	stopInfo := StopSyncInfo{Id: jobId}
	data, _ := json.Marshal(stopInfo)
	transInfo := TransInfo{
		Action: stopAction,
		Data:   string(data),
	}
	jm.syncSend(transInfo)

	return
}

func (jm *jobManager) distribute(jobId string, k, v interface{}) {
	jm.mu.Lock()
	runner, ok := jm.runningMap[jobId]
	if ok {
		_ = runner.job.Distribute(k, v)
	}
	jm.mu.Unlock()
}

func (jm *jobManager) retry(jobId string) {
	jm.mu.Lock()
	runner, ok := jm.runningMap[jobId]
	if ok {
		runner.job.Retry()
	}
	jm.mu.Unlock()
}

func (jm *jobManager) finish(jobId string) {
	jm.mu.Lock()
	if runner, ok := jm.runningMap[jobId]; ok {
		runner.job.Finish()
	}
	jm.mu.Unlock()
}

//

func NewJob(name string, conNum int, timeout int) (string, error) {
	job, err := JM.newJob(name, conNum, timeout)
	if err != nil {
		return "", err
	}
	return job.GetId(), err
}

func DistributeJob(jobId string, k, v interface{}) {
	JM.distribute(jobId, k, v)
}

func Finish(jobId string) {
	JM.finish(jobId)
}

func StopJob(jobId string) {
	JM.stopJob(jobId)
}

func SyncRecv(transInfo TransInfo) {
	JM.syncRecv(transInfo)
}

func GetStat(jobId string) map[string]interface{} {
	ctx := context.Background()
	statMap := make(map[string]interface{})
	statKey := fmt.Sprintf(JobStat, jobId)
	infoKey := fmt.Sprintf(JobInfo, jobId)

	statMap["info"] = infra.Grds.HGetAll(ctx, infoKey).Val()
	statMap["stat"] = infra.Grds.HGetAll(ctx, statKey).Val()

	return statMap
}

func GetResult(jobId string) []string {
	ctx := context.Background()
	r := make([]string, 0)
	respKey := fmt.Sprintf(JobResp, jobId)

	for i := int64(0); i < infra.Grds.LLen(ctx, respKey).Val(); i++ {
		val := infra.Grds.LIndex(ctx, respKey, i).Val()
		r = append(r, val)
	}
	return r
}

func Retry(jobId string) {
	JM.retry(jobId)
}

func GetFailedList(jobId string) []string {
	ctx := context.Background()
	r := make([]string, 0)
	retryKey := fmt.Sprintf(JobRetry, jobId)
	for i := int64(0); i < infra.Grds.LLen(ctx, retryKey).Val(); i++ {
		jobData := infra.Grds.LIndex(ctx, retryKey, i).Val()
		r = append(r, jobData)
	}
	return r
}
