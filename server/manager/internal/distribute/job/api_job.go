package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/midware"
	"github.com/bytedance/Elkeid/server/manager/infra"
	. "github.com/bytedance/Elkeid/server/manager/infra/def"
	"github.com/bytedance/Elkeid/server/manager/infra/discovery"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/dbtask"
	"github.com/go-redis/redis/v8"
	"github.com/levigross/grequests"
)

const (
	HttpMethodGet  = "GET"
	HttpMethodPost = "POST"
)

var (
	AJF    *apiJobFunc
	ApiMap map[string]map[string]interface{}
)

func InitApiMap() {
	ApiMap = map[string]map[string]interface{}{
		//server api
		"Server_AgentStat": {
			"path":          "/conn/stat",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodGet,
			"scheme":        "https",
			"timeout":       15,
		},
		"Server_AgentList": {
			"path":          "/conn/list",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodGet,
			"scheme":        "https",
			"timeout":       15,
		},

		//agent api
		"Agent_Config": {
			"path":          "/command",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodPost,
			"scheme":        "https",
			"timeout":       15,
		},
		"Agent_Ctrl": {
			"path":          "/command",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodPost,
			"scheme":        "https",
			"timeout":       15,
		},
		"Agent_Task": {
			"path":          "/command",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodPost,
			"scheme":        "https",
			"timeout":       15,
		},
		"Agent_Quick_Config": {
			"path":          "/command",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodPost,
			"scheme":        "https",
			"timeout":       15,
			"port_num":      1,
		},
		"Agent_Config_v2": {
			"path":          "/command",
			"register_name": fmt.Sprintf(infra.ServerRegisterFormat, infra.SvrName),
			"method":        HttpMethodPost,
			"scheme":        "https",
			"timeout":       15,
			"port_num":      1,
		},
	}
}

func AgentListRlt(jid string, v interface{}) (interface{}, error) {
	jPack, ok := v.(JobResWithArgs)
	if ok && jPack.Response != nil && jPack.Response.StatusCode == 200 {
		r := SrvConnListResp{Data: []string{}}
		if err := json.Unmarshal(jPack.Response.Bytes(), &r); err != nil {
			ylog.Errorf("agentListRlt", "jodID %s, error %s; res:%s", jid, err.Error(), jPack.Response.String())
			return nil, err
		}
		//key list , value jPack.Args.Host
		pipeline := infra.Grds.Pipeline()
		for _, v := range r.Data {
			pipeline.Set(context.Background(), v, jPack.Args.Host, 60*time.Minute)
		}
		_, err := pipeline.Exec(context.Background())
		if err != nil && err != redis.Nil {
			ylog.Errorf("agentListRlt", "redis pipeline err:%v", err)
		}
	}
	return nil, nil
}

func AgentHBRlt(jid string, v interface{}) (interface{}, error) {
	jPack, ok := v.(JobResWithArgs)
	if ok && jPack.Response != nil && jPack.Response.StatusCode == 200 {
		r := SrvConnStatResp{}
		if err := json.Unmarshal(jPack.Response.Bytes(), &r); err != nil {
			ylog.Errorf("agentHBRlt", "jodID %s, error %s; res:%s", jid, err.Error(), jPack.Response.String())
			return nil, err
		}
		arr := strings.Split(jPack.Args.Host, ":")
		if len(arr) != 2 {
			return nil, nil
		}
		port, err := strconv.ParseInt(arr[1], 10, 64)
		if err != nil {
			ylog.Errorf("agentHBRlt", "error %s; res:%s", err.Error(), jPack.Response.String())
			return nil, err
		}

		for i := range r.Data {
			if r.Data[i].AgentInfo != nil {
				r.Data[i].AgentInfo["source_ip"] = arr[0]
				r.Data[i].AgentInfo["source_port"] = port
			}
			dbtask.HBAsyncWrite(r.Data[i])
		}
	}
	return nil, nil
}

type apiJobFunc struct {
	disMap map[string]DisJob
	doMap  map[string]DoJob
	rltMap map[string]DoRlt
}

func NewApiJobFunc() *apiJobFunc {
	jf := &apiJobFunc{
		disMap: make(map[string]DisJob),
		doMap:  make(map[string]DoJob),
		rltMap: make(map[string]DoRlt),
	}

	return jf
}

func (jf *apiJobFunc) Register(name string, dis DisJob, do DoJob, rlt DoRlt) {
	if dis != nil {
		jf.disMap[name] = dis
	} else {
		jf.disMap[name] = defaultApiDistribute
	}
	if do != nil {
		jf.doMap[name] = do
	} else {
		jf.doMap[name] = defaultApiDo
	}
	if rlt != nil {
		jf.rltMap[name] = rlt
	} else {
		jf.rltMap[name] = defaultApiRltCallback
	}
}

func defaultApiDistribute(jid string, k, v interface{}) (interface{}, error) {
	ylog.Debugf("defaultApiDistribute", ">>>>api job distribute job")
	jobs := make([]JobArgs, 0)
	name := k.(string)
	hosts, err := discovery.FetchRegistry(ApiMap[name]["register_name"].(string))
	if err != nil {
		return jobs, err
	}
	ylog.Debugf("defaultApiDistribute", "jodID %s,fetch %s hosts: %v, value: %#v", jid, name, hosts, v)
	for _, host := range hosts {
		ja := JobArgs{
			Name:    name,
			Host:    host,
			Args:    nil,
			Scheme:  ApiMap[name]["scheme"].(string),
			Method:  ApiMap[name]["method"].(string),
			Timeout: ApiMap[name]["timeout"].(int),
			Path:    ApiMap[name]["path"].(string),
		}
		jobs = append(jobs, ja)
	}
	return jobs, err
}

func defaultApiDo(jid string, args interface{}) (interface{}, error) {
	var (
		r      *grequests.Response
		err    error
		result string
	)
	ja := JobArgs{
		Args: make(map[string]interface{}),
	}
	err = json.Unmarshal([]byte(args.(string)), &ja)
	if err != nil {
		ylog.Errorf("defaultApiDo", "[api_job] jodID %s, do error: %s", jid, err.Error())
		return nil, err
	}

	url := fmt.Sprintf("%s://%s%s", ja.Scheme, ja.Host, ja.Path)
	ylog.Debugf("defaultApiDo", "[api_jobs] do: %s %s", url, args.(string))

	option := midware.SvrAuthRequestOption()
	option.JSON = ja.Args
	option.RequestTimeout = time.Duration(ja.Timeout) * time.Second

	switch ja.Method {
	case HttpMethodGet:
		r, err = grequests.Get(url, option)
	case HttpMethodPost:
		r, err = grequests.Post(url, option)
	default:
		return nil, errors.New("request method not support")
	}

	if err != nil {
		result = fmt.Sprintf("url:%s; Result:%s", url, err.Error())
	}
	if r.Ok {
		result = fmt.Sprintf("url:%s; Result:%s", url, r.String())
	} else {
		result = fmt.Sprintf("url:%s; Result:StatusCode is %d", url, r.StatusCode)
	}

	return JobResWithArgs{Args: &ja, Response: r, Result: result}, err
}

func defaultApiRltCallback(jid string, v interface{}) (interface{}, error) {
	ylog.Debugf("defaultApiRltCallback", "jodID %s, value: %#v", jid, v)
	return nil, nil

}

type ApiJob struct {
	SimpleJob
}

func NewApiJob(id string, name string, conNum int, timeout int, needRes bool, rds redis.UniversalClient) Job {
	if _, ok := ApiMap[name]; !ok {
		return nil
	}
	sj := NewSimpleJob(id, name, 0, ApiMap[name], nil, conNum, timeout, needRes, AJF.disMap[name], AJF.doMap[name], AJF.rltMap[name], rds)

	aj := &ApiJob{
		SimpleJob: sj,
	}
	return aj
}
