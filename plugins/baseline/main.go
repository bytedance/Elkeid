package main

import (
	"baseline/infra"
	"baseline/src/check"
	"baseline/src/linux"
	"encoding/json"
	"github.com/bytedance/plugins"
	"math/rand"
	"runtime"
	"time"
)

var (
	BaseLineDataType           = 8000
	BaseLineTaskStatusDataType = 8010
	TaskStatusSuccess          = "succeed"
	TaskStatusFailed           = "failed"
	CentosDefaultList          = []int{1200}
	DebianDefaultList          = []int{1300}
	UbuntuDefaultList          = []int{1400}
	pluginClient               *plugins.Client
)

func init() {
	runtime.GOMAXPROCS(4)
	pluginClient = plugins.New()
	return
}

// SendServer send result to server
func SendServer(retCheckInfo check.RetBaselineInfo, token string) (err error) {
	record := plugins.Record{}
	record.DataType = int32(BaseLineDataType)
	record.Timestamp = time.Now().Unix()

	dataInfo, err := json.Marshal(retCheckInfo)
	if err != nil {
		return err
	}

	payload := plugins.Payload{}
	field := make(map[string]string, 0)
	field["data"] = string(dataInfo)
	field["token"] = token
	payload.Fields = field
	record.Data = &payload

	err = pluginClient.SendRecord(&record)
	if err != nil {
		return err
	}
	return nil
}

// TaskStatusSendServer send task result to server
func TaskStatusSendServer(status string, token string, msg string) {
	record := plugins.Record{}
	record.DataType = int32(BaseLineTaskStatusDataType)
	record.Timestamp = time.Now().Unix()

	payload := plugins.Payload{}
	field := make(map[string]string, 0)
	field["status"] = status
	if token != "" {
		field["token"] = token
	}
	field["msg"] = msg
	payload.Fields = field
	record.Data = &payload

	_ = pluginClient.SendRecord(&record)
}

func main() {
	go func() {
		for {
			// get result from leader
			pluginsTask, err := pluginClient.ReceiveTask()
			if err != nil {
				infra.Loger.Println("getTask error:", err.Error())
				break
			}
			go func() {
				// start baseline analysis
				retBaselineInfo, analysisErr := check.Analysis(pluginsTask.Data)

				// send request to server
				err = SendServer(retBaselineInfo, pluginsTask.Token)
				if err != nil {
					infra.Loger.Println("sendServer error:", err)
				} else {
					infra.Loger.Println("sendServer success:", retBaselineInfo.BaselineId)
				}

				// report task result
				if analysisErr != nil {
					TaskStatusSendServer(TaskStatusFailed, pluginsTask.Token, analysisErr.Error())
				} else {
					TaskStatusSendServer(TaskStatusSuccess, pluginsTask.Token, "")
				}
			}()
		}
	}()

	// cronjob
	init := true
	dailyTicker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))

	defer dailyTicker.Stop()
	for {
		select {
		// daily task
		case <-dailyTicker.C:
			if init {
				dailyTicker.Reset(time.Hour * 24)
				init = false
			}

			var baselineIdList []int
			// start analysis by system
			switch linux.GetSystemType() {
			case "centos":
				baselineIdList = CentosDefaultList
			case "debian":
				baselineIdList = DebianDefaultList
			case "ubuntu":
				baselineIdList = UbuntuDefaultList
			default:
				return
			}

			// start analysis
			for _, baselineId := range baselineIdList {
				retBaselineInfo, analysisErr := check.Analysis(baselineId)

				// send request to sever
				err := SendServer(retBaselineInfo, "")
				if err != nil {
					infra.Loger.Println("sendServer error", err)
				} else {
					infra.Loger.Println("sendServer success:", retBaselineInfo)
				}

				// report task result
				if analysisErr != nil {
					TaskStatusSendServer(TaskStatusFailed, "", analysisErr.Error())
				} else {
					TaskStatusSendServer(TaskStatusSuccess, "", "")
				}
			}
		}
	}
}
