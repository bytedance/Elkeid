package check

import (
	"baseline/infra"
	"encoding/json"
	"fmt"
	"strconv"
)


type RetBaselineInfo struct {
	BaselineId      int            `json:"baseline_id" bson:"baseline_id"`
	BaselineVersion string         `json:"baseline_version" bson:"baseline_version"`
	Status          string         `json:"status" bson:"status"`
	Msg             string         `json:"msg" bson:"msg"`
	CheckList       []RetCheckInfo `json:"check_list" bson:"check_list"`
}

type RetCheckInfo struct {
	CheckId       int    `json:"check_id" bson:"check_id"`
	TitleCn       string `json:"title_cn" bson:"title_cn"`
	DescriptionCn string `json:"description_cn" bson:"description_cn"`
	SolutionCn    string `json:"solution_cn" bson:"solution_cn"`
	Result        int    `json:"result" bson:"result"`
	Msg           string `json:"msg" bson:"msg"`
}

type TaskData struct {
	BaselineId  int   `json:"baseline_id"`
	CheckIdList []int `json:"check_id_list"`
}

var (
	BaselineStatusError   = "error"
	BaselineStatusSuccess = "success"
)

// get baselin config info
func getBaselineConfigData(baselineId int) (baselineInfo BaselineInfo, err error) {

	// bind config file
	var yamlPath string
	if baselineId < 6000 {
		yamlPath = fmt.Sprintf("config/linux/%d.yaml", baselineId)
	} else {
		yamlPath = fmt.Sprintf("config/container/%d.yaml", baselineId)
	}
	err = infra.BindYaml(yamlPath, &baselineInfo)
	if err != nil {
		return
	}
	return
}

// AnalysisBaseline start baseline task
func AnalysisBaseline(taskData TaskData) (retBaselineInfo RetBaselineInfo, err error) {

	// analysis params
	baselineId := taskData.BaselineId
	checkIdList := taskData.CheckIdList
	retBaselineInfo.BaselineId = baselineId

	baselineInfo, err := getBaselineConfigData(baselineId)
	if err != nil {
		infra.Loger.Println("getBaselineConfigData error:", err)
		return retBaselineInfo, err
	}

	retBaselineInfo.BaselineVersion = baselineInfo.BaselineVersion

	// get and analysis check rule
	taskCheckIdMap := make(map[int]int)
	for _, checkId := range checkIdList {
		taskCheckIdMap[checkId] = 0
	}
	for _, checkInfo := range baselineInfo.CheckList {
		if len(checkIdList) != 0 {
			if _, ok := taskCheckIdMap[checkInfo.CheckId]; !ok {
				continue
			}
		}
		var retcheckInfo RetCheckInfo
		retcheckInfo.CheckId = checkInfo.CheckId
		retcheckInfo.TitleCn = checkInfo.TitleCn
		retcheckInfo.DescriptionCn = checkInfo.DescriptionCn
		retcheckInfo.SolutionCn = checkInfo.SolutionCn
		ifPass, err := AnalysisRule(checkInfo.Check)
		if err != nil {
			retcheckInfo.Result = ErrorCode
			errCode, _ := strconv.Atoi(err.Error()[:2])
			switch errCode {
			case ErrorFile:
				retcheckInfo.Result = ErrorFile
				retcheckInfo.Msg = err.Error()[3:]
			case ErrorConfigWrite:
				retcheckInfo.Result = ErrorConfigWrite
				retcheckInfo.Msg = err.Error()[3:]
			default:
				retcheckInfo.Result = ErrorCode
				retcheckInfo.Msg = err.Error()
			}
		} else {
			if ifPass {
				retcheckInfo.Result = SuccessCode
			} else {
				retcheckInfo.Result = FailCode
			}
		}
		retBaselineInfo.CheckList = append(retBaselineInfo.CheckList, retcheckInfo)
	}
	return retBaselineInfo, err
}

// Analysis config file
func Analysis(data interface{}) (retBaselineInfo RetBaselineInfo, err error) {
	var taskData TaskData
	switch data.(type) {
	case int:
		taskData.BaselineId = data.(int)
	case string:
		// analysis parameter
		err = json.Unmarshal([]byte(data.(string)), &taskData)
		if err != nil {
			retBaselineInfo.Status = BaselineStatusError
			retBaselineInfo.Msg = err.Error()
			return retBaselineInfo, err
		}
	}

	// start analysis
	retBaselineInfo, err = AnalysisBaseline(taskData)
	if err != nil {
		retBaselineInfo.Status = BaselineStatusError
		retBaselineInfo.Msg = err.Error()
	} else {
		retBaselineInfo.Status = BaselineStatusSuccess
	}
	return retBaselineInfo, err
}
