package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/levigross/grequests"
)

const (
	newAction  = "new"
	stopAction = "stop"

	syncURL = "http://%s/api/v0/inner/sync"
)

var (
	JM *jobManager
	CM *cronJobManager
)

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
	return cj
}

func (cm *cronJobManager) Add(name string, interval int, conNum int, timeout int) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.jobs = append(cm.jobs, cronJob{name: name, interval: interval, conNum: conNum, timeout: timeout})
}

func (cm *cronJobManager) Manage() {
	ylog.Debugf("cronJobManager", "cron jobs: %v", cm.jobs)
	for _, cj := range cm.jobs {
		go func(cj cronJob) {
			t := time.NewTicker(time.Duration(cj.interval) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					lock := fmt.Sprintf(cronLock, cj.name, time.Now().Unix()/int64(cj.interval))
					ok := infra.Grds.SetNX(context.Background(), lock, 1, time.Duration(cj.interval)*time.Second).Val()
					ylog.Debugf("cronJobManager", "set lock %s %v", lock, ok)
					if !ok {
						break
					}
					jobId, err := NewCronJob(cj.name, cj.conNum, cj.timeout)
					if err != nil {
						ylog.Debugf("cronJobManager", "[cronJobManager] new job error: %s", err.Error())
						break
					}
					ylog.Debugf("cronJobManager", "[cronJobManager] new job: %s", jobId)
					time.Sleep(10 * time.Millisecond)
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
	NeedRes bool   `json:"need_res"`
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
	mu         sync.Mutex
	runningMap map[string]*runner
	over       chan bool
}

func NewJobManager() *jobManager {
	jm := &jobManager{
		runningMap: make(map[string]*runner),
		over:       make(chan bool),
	}

	return jm
}

func (jm *jobManager) inform(r *runner) {
	job := r.job
	over := r.over
	go job.Run(over)
	jm.mu.Lock()
	jm.runningMap[job.GetId()] = r
	jm.mu.Unlock()
	ylog.Infof("jobManager", "informed new a job: %s", job.GetId())
	//监控结束
	go func(r *runner) {
		select {
		case <-r.over:
			ylog.Debugf("jobManager", "job %s informed finish", r.job.GetId())
			jm.mu.Lock()
			delete(jm.runningMap, r.job.GetId())
			jm.mu.Unlock()
			return
		}
	}(r)
}

func (jm *jobManager) newJob(name string, conNum int, timeout int, needRes bool) (Job, error) {
	job := NewApiJob("", name, conNum, timeout, needRes, infra.Grds)
	if job == nil {
		return nil, errors.New("new job failed")
	}

	jm.inform(&runner{name: name, job: job, over: make(chan bool)})

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
		job := NewApiJob(newInfo.Id, newInfo.Name, newInfo.ConNum, newInfo.Timeout, newInfo.NeedRes, infra.Grds)
		if job == nil {
			return
		}

		jm.inform(&runner{name: newInfo.Name, job: job, over: make(chan bool)})
	case stopAction:
		stopInfo := StopSyncInfo{}
		if err := json.Unmarshal([]byte(transInfo.Data), &stopInfo); err != nil {
			ylog.Errorf("jobManager", "[manager] json unmarshal error: %s", err.Error())
			return
		}
		jm.mu.Lock()
		runner, ok := jm.runningMap[stopInfo.Id]
		jm.mu.Unlock()
		if ok {
			runner.job.Stop()
		}
	default:
		ylog.Infof("jobManager", "[manager] action not support")
	}
}

func (jm *jobManager) stopJob(jobId string) {
	jm.mu.Lock()
	runner, ok := jm.runningMap[jobId]
	jm.mu.Unlock()
	if ok {
		runner.job.Stop()
	}

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
	jm.mu.Unlock()
	if ok {
		err := runner.job.Distribute(jobId, k, v)
		if err != nil {
			ylog.Errorf("jobManager", "[distribute] jid %s, error %s", jobId, err.Error())
		}
	} else {
		ylog.Errorf("jobManager", "[distribute] jid %s not found!", jobId)
	}
}

func (jm *jobManager) retry(jobId string) {
	jm.mu.Lock()
	runner, ok := jm.runningMap[jobId]
	jm.mu.Unlock()
	if ok {
		runner.job.Retry()
	}
}

func (jm *jobManager) finish(jobId string) {
	jm.mu.Lock()
	runner, ok := jm.runningMap[jobId]
	jm.mu.Unlock()
	if ok {
		runner.job.Finish()
	}
}

func NewCronJob(name string, conNum int, timeout int) (string, error) {
	return NewJob(name, conNum, timeout, false)
}

func NewJob(name string, conNum int, timeout int, needRes bool) (string, error) {
	job, err := JM.newJob(name, conNum, timeout, needRes)
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
	statMap := make(map[string]interface{})
	statKey := fmt.Sprintf(JobStat, jobId)
	infoKey := fmt.Sprintf(JobInfo, jobId)

	statMap["info"] = infra.Grds.HGetAll(context.Background(), infoKey).Val()
	statMap["stat"] = infra.Grds.HGetAll(context.Background(), statKey).Val()

	return statMap
}

func GetResult(jobId string) []string {
	r := make([]string, 0)
	respKey := fmt.Sprintf(JobResp, jobId)

	for i := int64(0); i < infra.Grds.LLen(context.Background(), respKey).Val(); i++ {
		val := infra.Grds.LIndex(context.Background(), respKey, i).Val()
		r = append(r, val)
	}
	return r
}
