package v6

import (
	"time"

	"github.com/bytedance/Elkeid/server/manager/biz/common"
	"github.com/bytedance/Elkeid/server/manager/infra/ylog"
	"github.com/bytedance/Elkeid/server/manager/internal/alarm"

	"github.com/gin-gonic/gin"
)

// ############################### Data Struct ###############################
type AlarmOverviewResponse struct {
	TotalUnhandleAlarmNum int64                         `json:"total_unhandle_alarm_num,omitempty"`
	HostAlarm             alarm.AlarmOverviewStat       `json:"host_alarm,omitempty"`
	RaspAlarm             alarm.AlarmOverviewStat       `json:"rasp_alarm,omitempty"`
	KubeAlarm             alarm.AlarmOverviewStat       `json:"kube_alarm,omitempty"`
	SevenDayTrend         []alarm.AlarmOverviewDayTrend `json:"seven_day_trend,omitempty"`
}

// ############################### Function ###############################
func GetOverviewAlarmStat(c *gin.Context) {
	var rsp AlarmOverviewResponse
	trendDay := 7
	nowTime := time.Now().Unix()

	// get host alarm
	hostStat, hostTrend, hErr := alarm.QueryAlarmDayStat(c, nowTime, alarm.AlarmTypeHids, trendDay)
	if hErr != nil {
		ylog.Errorf("QueryAlarmDayStat for HOST error", hErr.Error())
	}

	// get rasp alarm
	raspStat, raspTrend, rErr := alarm.QueryAlarmDayStat(c, nowTime, alarm.AlarmTypeRasp, trendDay)
	if rErr != nil {
		ylog.Errorf("QueryAlarmDayStat for RASP error", rErr.Error())
	}

	// get kube alarm
	kubeStat, kubeTrend, kErr := alarm.QueryAlarmDayStat(c, nowTime, alarm.AlarmTypeKube, trendDay)
	if kErr != nil {
		ylog.Errorf("QueryAlarmDayStat for KUBE error", kErr.Error())
	}

	rsp.TotalUnhandleAlarmNum = hostStat.TotalNum + raspStat.TotalNum + kubeStat.TotalNum
	rsp.HostAlarm = *hostStat
	rsp.RaspAlarm = *raspStat
	rsp.KubeAlarm = *kubeStat

	for i := 1; i <= trendDay; i++ {
		tmpDayIndex := i - trendDay
		tmpTimeIndex := alarm.GetAlarmDayStatDayTimeIndex(nowTime, tmpDayIndex)
		tmpTrend := alarm.AlarmOverviewDayTrend{
			DayTime:          tmpTimeIndex,
			UnhandleAlarmNum: 0,
		}
		hOne, hOk := hostTrend[tmpTimeIndex]
		if hOk {
			tmpTrend.UnhandleAlarmNum = tmpTrend.UnhandleAlarmNum + hOne.UnhandleAlarmNum
			tmpTrend.HidsUnhandleAlarmNum = hOne.UnhandleAlarmNum
		}

		rOne, rOk := raspTrend[tmpTimeIndex]
		if rOk {
			tmpTrend.UnhandleAlarmNum = tmpTrend.UnhandleAlarmNum + rOne.UnhandleAlarmNum
			tmpTrend.RaspUnhandleAlarmNum = rOne.UnhandleAlarmNum
		}

		kOne, kOk := kubeTrend[tmpTimeIndex]
		if kOk {
			tmpTrend.UnhandleAlarmNum = tmpTrend.UnhandleAlarmNum + kOne.UnhandleAlarmNum
			tmpTrend.KubeUnhandleAlarmNum = kOne.UnhandleAlarmNum
		}
		rsp.SevenDayTrend = append(rsp.SevenDayTrend, tmpTrend)
	}

	CreateResponse(c, common.SuccessCode, rsp)
}
